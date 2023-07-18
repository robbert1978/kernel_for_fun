struct tty_operations {
	void * (*lookup)(void *driver,
			void *filp, int idx);
	int  (*install)(void *driver, void *tty);
	void (*remove)(void *driver, void *tty);
	int  (*open)(void * tty, void * filp);
	void (*close)(void * tty, void * filp);
	void (*shutdown)(void *tty);
	void (*cleanup)(void *tty);
	int  (*write)(void * tty,
		      const unsigned char *buf, int count);
	int  (*put_char)(void *tty, unsigned char ch);
	void (*flush_chars)(void *tty);
	int  (*write_room)(void *tty);
	int  (*chars_in_buffer)(void *tty);
	int  (*ioctl)(void *tty,
		    unsigned int cmd, unsigned long arg);
	long (*compat_ioctl)(void *tty,
			     unsigned int cmd, unsigned long arg);
	void (*set_termios)(void *tty, void * old);
	void (*throttle)(void * tty);
	void (*unthrottle)(void * tty);
	void (*stop)(void *tty);
	void (*start)(void *tty);
	void (*hangup)(void *tty);
	int (*break_ctl)(void *tty, int state);
	void (*flush_buffer)(void *tty);
	void (*set_ldisc)(void *tty);
	void (*wait_until_sent)(void *tty, int timeout);
	void (*send_xchar)(void *tty, char ch);
	int (*tiocmget)(void *tty);
	int (*tiocmset)(void *tty,
			unsigned int set, unsigned int clear);
	int (*resize)(void *tty, void *ws);
	int (*set_termiox)(void *tty, void *tnew);
	int (*get_icount)(void *tty,
				void *icount);
	void (*show_fdinfo)(void *tty, void *m);
#ifdef CONFIG_CONSOLE_POLL
	int (*poll_init)(void *driver, int line, char *options);
	int (*poll_get_char)(void *driver, int line);
	void (*poll_put_char)(void *driver, int line, char ch);
#endif
	int (*proc_show)(void *, void *);
};