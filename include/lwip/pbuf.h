/*
 * A stub for the pbuf.h header file.
 */
#ifndef LWIP_PBUF_H

#define LWIP_PBUF_H

#ifdef __cplusplus
	extern "C" {
#endif

#define PBUF_TYPE_ALLOC_SRC_MASK_STD_HEAP           0x00
#define PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF      0x01
#define PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF_POOL 0x02
/** First pbuf allocation type for applications */
#define PBUF_TYPE_ALLOC_SRC_MASK_APP_MIN            0x03
/** Last pbuf allocation type for applications */
#define PBUF_TYPE_ALLOC_SRC_MASK_APP_MAX            PBUF_TYPE_ALLOC_SRC_MASK

/* Base flags for pbuf_type definitions: */

/** Indicates that the payload directly follows the struct pbuf.
 *  This makes @ref pbuf_header work in both directions. */
#define PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS       0x80
/** Indicates the data stored in this pbuf can change. If this pbuf needs
 * to be queued, it must be copied/duplicated. */
#define PBUF_TYPE_FLAG_DATA_VOLATILE                0x40
/** 4 bits are reserved for 16 allocation sources (e.g. heap, pool1, pool2, etc)
 * Internally, we use: 0=heap, 1=MEMP_PBUF, 2=MEMP_PBUF_POOL -> 13 types free*/
#define PBUF_TYPE_ALLOC_SRC_MASK                    0x0F
/** Indicates this pbuf is used for RX (if not set, indicates use for TX).
 * This information can be used to keep some spare RX buffers e.g. for
 * receiving TCP ACKs to unblock a connection) */
#define PBUF_ALLOC_FLAG_RX                          0x0100
/** Indicates the application needs the pbuf payload to be in one piece */
#define PBUF_ALLOC_FLAG_DATA_CONTIGUOUS             0x0200

/**
 * @ingroup pbuf
 * Enumeration of pbuf layers
 */
typedef enum {
  PBUF_TRANSPORT,
  PBUF_IP,
  PBUF_LINK,
  PBUF_RAW_TX,
  PBUF_RAW
} pbuf_layer;

typedef enum {
  PBUF_RAM = (PBUF_ALLOC_FLAG_DATA_CONTIGUOUS | PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS | PBUF_TYPE_ALLOC_SRC_MASK_STD_HEAP),
  PBUF_ROM = PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF,
  PBUF_REF = (PBUF_TYPE_FLAG_DATA_VOLATILE | PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF),
  PBUF_POOL = (PBUF_ALLOC_FLAG_RX | PBUF_TYPE_FLAG_STRUCT_DATA_CONTIGUOUS | PBUF_TYPE_ALLOC_SRC_MASK_STD_MEMP_PBUF_POOL)
} pbuf_type;

/** Main packet buffer struct */
struct pbuf {
  /** next pbuf in singly linked pbuf chain */
  struct pbuf *next;

  /** pointer to the actual data in the buffer */
  void *payload;

  /**
   * total length of this buffer and all next buffers in chain
   * belonging to the same packet.
   *
   * For non-queue packet chains this is the invariant:
   * p->tot_len == p->len + (p->next? p->next->tot_len: 0)
   */
  u16_t tot_len;

  /** length of this buffer */
  u16_t len;

  /** a bit field indicating pbuf type and allocation sources
      (see PBUF_TYPE_FLAG_*, PBUF_ALLOC_FLAG_* and PBUF_TYPE_ALLOC_SRC_MASK)
    */
  u8_t type_internal;

  /** misc flags */
  u8_t flags;

  /**
   * the reference count always equals the number of pointers
   * that refer to this pbuf. This can be pointers from an application,
   * the stack itself, or pbuf->next pointers from a chain.
   */
  LWIP_PBUF_REF_T ref;

  /** For incoming packets, this contains the input netif's index */
  u8_t if_idx;

  /** In case the user needs to store data custom data on a pbuf */
  LWIP_PBUF_CUSTOM_DATA
};

struct pbuf *pbuf_alloc(pbuf_layer l, u16_t length, pbuf_type type);

u8_t pbuf_free(struct pbuf *p);

void pbuf_realloc(struct pbuf *p, u16_t size);

u16_t pbuf_copy_partial(const struct pbuf *p, void *dataptr, u16_t len, u16_t offset);

err_t pbuf_copy_partial_pbuf(struct pbuf *p_to, const struct pbuf *p_from, u16_t copy_len, u16_t offset);

struct pbuf *pbuf_skip(struct pbuf* in, u16_t in_offset, u16_t* out_offset);

err_t pbuf_take_at(struct pbuf *buf, const void *dataptr, u16_t len, u16_t offset);

int pbuf_try_get_at(const struct pbuf *p, u16_t offset);

struct pbuf * pbuf_clone(pbuf_layer layer, pbuf_type type, struct pbuf *p);

struct pbuf * pbuf_alloc_reference(void *payload, u16_t length, pbuf_type type);

#define pbuf_get_allocsrc( p )            ( ( p )->type_internal & PBUF_TYPE_ALLOC_SRC_MASK )
#define pbuf_match_allocsrc( p, type )    ( pbuf_get_allocsrc( p ) == ( ( type ) & PBUF_TYPE_ALLOC_SRC_MASK ) )

#ifdef __cplusplus
	} /* extern "C" */
#endif

#endif /* LWIP_PBUF_H */

