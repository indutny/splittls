#ifndef ENGINE_COMMON_H_
#define ENGINE_COMMON_H_

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define container_of(ptr, type, member) \
    ((type *) ((char *) (ptr) - offsetof(type, member)))

#endif  /* ENGINE_COMMON_H_ */
