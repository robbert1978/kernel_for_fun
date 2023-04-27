struct tty_operations {
	void (*lookup)(void);
	int  (*install)(void);
	void (*remove)(void);
	int  (*open)(void);
	void (*close)(void);
	void (*shutdown)(void);
	void (*cleanup)(void);
	int  (*write)(void * tty,
		      const unsigned char *buf, int count);
	int  (*put_char)(void*, unsigned char ch);
	void (*flush_chars)(void *);
	int  (*write_room)(void *);
	int  (*chars_in_buffer)(void *);
	int  (*ioctl)(void *,
		    unsigned int cmd, unsigned long arg);
	long (*compat_ioctl)(void *,
			     unsigned int cmd, unsigned long arg);
	void (*set_termios)(void *);
	void (*throttle)(void *);
	void (*unthrottle)(void *);
	void (*stop)(void *);
	void (*start)(void *);
	void (*hangup)(void *);
	int (*break_ctl)(void *);
	void (*flush_buffer)(void *);
	void (*set_ldisc)(void *);
	void (*wait_until_sent)(void *);
	void (*send_xchar)(void *, char ch);
	int (*tiocmget)(void *);
	int (*tiocmset)(void *,
			unsigned int set, unsigned int clear);
	int (*resize)(void *);
	int (*set_termiox)(void *);
	int (*get_icount)(void);
	void (*show_fdinfo)(void *);
#ifdef CONFIG_CONSOLE_POLL
	int (*poll_init)(void);
	int (*poll_get_char)(void);
	void (*poll_put_char)(void);
#endif
	int (*proc_show)(void);
};