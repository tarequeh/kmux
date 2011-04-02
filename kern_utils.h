#ifndef KERN_UTILS_H
#define KERN_UTILS_H

/* Few general purpose functions that kernel configuration handlers will need */

char *ltrim(char *s, char c) {
    while(*s == c) s++;
    return s;
}

char *rtrim(char *s, char c) {
    char* back = s + strlen(s);
    while(*--back == c);
    *(back+1) = '\0';
    return s;
}

char *trim(char *s, char c) {
    return rtrim(ltrim(s, c), c);
}

char *strtok_r(char *s, const char *delim, char **ptrptr) {
    char *tmp = 0;

    if (s == 0) s = *ptrptr;
    s += strspn(s, delim);       /* overread leading delimiter */
    if (*s) {
        tmp = s;
        s += strcspn(s, delim);
        if (*s) *s++ = 0;   /* not the end ? => terminate it */
    }

    *ptrptr = s;
    return tmp;
}

static int atoi(const char *s) {
    int k = 0;

    k = 0;
    while (*s != '\0' && *s >= '0' && *s <= '9') {
        k = 10 * k + (*s - '0');
        s++;
    }
    return k;
}

// Jenkins 32 bit integer has
static unsigned int j32int_hash(int key) {
    unsigned int hashed_key = (unsigned int)key;
    hashed_key = (hashed_key + 0x7ed55d16) + (hashed_key << 12);
    hashed_key = (hashed_key ^ 0xc761c23c) ^ (hashed_key >> 19);
    hashed_key = (hashed_key + 0x165667b1) + (hashed_key);
    hashed_key = (hashed_key + 0xd3a2646c) ^ (hashed_key << 9);
    hashed_key = (hashed_key + 0xfd7046c5) + (hashed_key);
    hashed_key = (hashed_key ^ 0xb55a4f09) ^ (hashed_key >> 16);
    return hashed_key;
}

#endif
