#ifndef BUFFER_H
#define BUFFER_H

#include <stdarg.h>

#ifdef WIN32
typedef unsigned char u_char;
typedef unsigned short u_short;
#endif


struct buffer {
	u_char *buffer;
	u_char *orig_buffer;

	size_t misalign;
	size_t totallen;
	size_t off;

	void (*cb)(struct buffer *, size_t, size_t, void *);
	void *cbarg;
};

/* Just for error reporting - use other constants otherwise */
#define BUFFER_READ		0x01
#define BUFFER_WRITE		0x02
#define BUFFER_EOF		0x10
#define BUFFER_ERROR		0x20
#define BUFFER_TIMEOUT	0x40

#define BUFFER_LENGTH(x)	(x)->off
#define BUFFER_DATA(x)	(x)->buffer
#define BUFFER_INPUT(x)	(x)->input
#define BUFFER_OUTPUT(x)	(x)->output

/**
  Allocate storage for a new buffer.

  @return a pointer to a newly allocated buffer struct, or NULL if an error
          occurred
 */
struct buffer *buffer_new(void);


/**
  Deallocate storage for an buffer.

  @param pointer to the buffer to be freed
 */
void buffer_free(struct buffer *);


/**
  Expands the available space in an event buffer.

  Expands the available space in the event buffer to at least datlen

  @param buf the event buffer to be expanded
  @param datlen the new minimum length requirement
  @return 0 if successful, or -1 if an error occurred
*/
int buffer_expand(struct buffer *, size_t);


/**
  Append data to the end of an buffer.

  @param buf the event buffer to be appended to
  @param data pointer to the beginning of the data buffer
  @param datlen the number of bytes to be copied from the data buffer
 */
int buffer_add(struct buffer *, const void *, size_t);



/**
  Read data from an event buffer and drain the bytes read.

  @param buf the event buffer to be read from
  @param data the destination buffer to store the result
  @param datlen the maximum size of the destination buffer
  @return the number of bytes read
 */
int buffer_remove(struct buffer *, void *, size_t);


/**
 * Read a single line from an event buffer.
 *
 * Reads a line terminated by either '\r\n', '\n\r' or '\r' or '\n'.
 * The returned buffer needs to be freed by the caller.
 *
 * @param buffer the buffer to read from
 * @return pointer to a single line, or NULL if an error occurred
 */
char *buffer_readline(struct buffer *);


/**
  Move data from one buffer into another buffer.

  This is a destructive add.  The data from one buffer moves into
  the other buffer. The destination buffer is expanded as needed.

  @param outbuf the output buffer
  @param inbuf the input buffer
  @return 0 if successful, or -1 if an error occurred
 */
int buffer_add_buffer(struct buffer *, struct buffer *);


/**
  Append a formatted string to the end of an buffer.

  @param buf the buffer that will be appended to
  @param fmt a format string
  @param ... arguments that will be passed to printf(3)
  @return The number of bytes added if successful, or -1 if an error occurred.
 */
int buffer_add_printf(struct buffer *, const char *fmt, ...)
#ifdef __GNUC__
  __attribute__((format(printf, 2, 3)))
#endif
;


/**
  Append a va_list formatted string to the end of an buffer.

  @param buf the buffer that will be appended to
  @param fmt a format string
  @param ap a varargs va_list argument array that will be passed to vprintf(3)
  @return The number of bytes added if successful, or -1 if an error occurred.
 */
int buffer_add_vprintf(struct buffer *, const char *fmt, va_list ap);


/**
  Remove a specified number of bytes data from the beginning of an buffer.

  @param buf the buffer to be drained
  @param len the number of bytes to drain from the beginning of the buffer
  @return 0 if successful, or -1 if an error occurred
 */
void buffer_drain(struct buffer *, size_t);


/**
  Write the contents of an buffer to a file descriptor.

  The buffer will be drained after the bytes have been successfully written.

  @param buffer the buffer to be written and drained
  @param fd the file descriptor to be written to
  @return the number of bytes written, or -1 if an error occurred
  @see buffer_read()
 */
int buffer_write(struct buffer *, int);


/**
  Read from a file descriptor and store the result in an buffer.

  @param buf the buffer to store the result
  @param fd the file descriptor to read from
  @param howmuch the number of bytes to be read
  @return the number of bytes read, or -1 if an error occurred
  @see buffer_write()
 */
int buffer_read(struct buffer *, int, int);


/**
  Find a string within an buffer.

  @param buffer the buffer to be searched
  @param what the string to be searched for
  @param len the length of the search string
  @return a pointer to the beginning of the search string, or NULL if the search failed.
 */
u_char *buffer_find(struct buffer *, const u_char *, size_t);

/**
  Set a callback to invoke when the buffer is modified.

  @param buffer the buffer to be monitored
  @param cb the callback function to invoke when the buffer is modified
  @param cbarg an argument to be provided to the callback function
 */
void buffer_setcb(struct buffer *, void (*)(struct buffer *, size_t, size_t, void *), void *);


#endif
