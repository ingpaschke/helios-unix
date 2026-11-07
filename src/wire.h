#ifndef HU_PRIVATE_WIRE_H
#define HU_PRIVATE_WIRE_H
#include <string.h>

/* Private fixed-size records use little-endian 32-bit words. Callers check
 * the record size before decoding; native structures never overlay bytes. */
struct wire_reader {
    const unsigned char *next;
};

struct wire_writer {
    unsigned char *next;
};

static inline unsigned wire_read_word(struct wire_reader *reader)
{
    const unsigned char *p = reader->next;
    unsigned value = (unsigned)p[0] | (unsigned)p[1] << 8 | (unsigned)p[2] << 16 |
                     (unsigned)p[3] << 24;
    reader->next += 4;
    return value;
}

static inline void wire_read_bytes(struct wire_reader *reader, void *out, unsigned size)
{
    memcpy(out, reader->next, size);
    reader->next += size;
}

static inline void wire_write_word(struct wire_writer *writer, unsigned value)
{
    unsigned char *p = writer->next;
    p[0] = value;
    p[1] = value >> 8;
    p[2] = value >> 16;
    p[3] = value >> 24;
    writer->next += 4;
}

static inline void wire_write_bytes(struct wire_writer *writer, const void *data,
                                    unsigned size)
{
    memcpy(writer->next, data, size);
    writer->next += size;
}

static inline void wire_write_string(struct wire_writer *writer, const char *text,
                                     unsigned size)
{
    unsigned length = strlen(text);
    memcpy(writer->next, text, length);
    memset(writer->next + length, 0, size - length);
    writer->next += size;
}
#endif
