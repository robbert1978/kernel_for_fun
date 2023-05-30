#define FUSE_USE_VERSION 29
#include <errno.h>
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

char* content = "Hello World\n";

int getattr_callback(const char* path,struct stat* stbuf){
    fputs("[*] getattr called\n",stderr);
    memset(stbuf,0,sizeof(struct stat));
    if(strcmp(path,"/file") == 0){
        stbuf->st_mode =  S_IFREG | 0777;
        stbuf->st_nlink = 1;
        stbuf->st_size = strlen(content);
        return 0;
    }
    return -ENOENT;
}
int open_callback(const char *path, struct fuse_file_info *fi) {
  fputs("[+] open_callback\n",stderr);
  return 0;
}
int read_callback(const char *path,
                char *buf, size_t size, off_t offset,
                struct fuse_file_info *fi){
        fputs("[+] read_callback\n",stderr);
        if (strcmp(path, "/file") == 0){
            size_t len = strlen(content);
            if(offset > len)
                return 0;
            if ((size > len) || (offset + size > len)){
                memcpy(buf, content + offset, len - offset);
                return len - offset;
            }
            else{
                memcpy(buf, content + offset, size);
                return size;
            }
        }
        return -ENOENT;
}
struct fuse_operations fops = {
  .getattr = getattr_callback,
  .open = open_callback,
  .read = read_callback,
};

// int main(int argc, char **argv,char** envp){
//     return fuse_main(argc, argv, &fops, NULL);
// }
int main(int argc, char **argv,char** envp){
    struct fuse_args args = FUSE_ARGS_INIT(0,NULL);
    struct fuse_chan* chan;
    struct fuse* fuse;
    if((chan = fuse_mount("/tmp/fuse_mount",&args)) == NULL){
        perror("fuse_mount");
        exit(-1);
    }
    if((fuse = fuse_new(chan,&args,&fops,sizeof(fops),NULL)) == NULL){
        fuse_unmount("/tmp/fuse_mount",chan);
        perror("fuse_new");
        exit(-1);
    }
    fuse_set_signal_handlers(fuse_get_session(fuse));
    fuse_loop_mt(fuse);

    fuse_unmount("/tmp/fuse_mount",chan);

    return 0;
}