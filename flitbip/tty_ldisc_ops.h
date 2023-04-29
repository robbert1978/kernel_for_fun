struct tty_ldisc_ops {
	int	magic;
	char	*name;
	int	num;
	int	flags;

	/*
	 * The following routines are called from above.
	 */
	int	    (*open)(void *);
	void	(*close)(void *);
	void	(*flush_buffer)(void *tty);
	long	(*read)(void *tty, void * file,
			unsigned char  *buf, long nr);
	long	(*write)(void *tty, void * file,
			 const unsigned char *buf, long nr);
	int	(*ioctl)(void *tty, void * file,
			 unsigned int cmd, unsigned long arg);
	long	(*compat_ioctl)(void *tty, void * file,
				unsigned int cmd, unsigned long arg);
	void	(*set_termios)(void *tty, void *old);
	void (*poll)(void *, void *,
			    void *);
	int	(*hangup)(void *tty);

	/*
	 * The following routines are called from below.
	 */
	void	(*receive_buf)(void *, const unsigned char *cp,
			       char *fp, int count);
	void	(*write_wakeup)(void *);
	void	(*dcd_change)(void *, unsigned int);
	int	(*receive_buf2)(void *, const unsigned char *cp,
				char *fp, int count);

	struct  module *owner;

	int refcount;
};