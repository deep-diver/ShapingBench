#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *json_part_names[] = {
  "url", "scheme", "user", "password", "options", "host",
  "port", "path", "query", "fragment", "zoneid"
};

static CURLUPart curl_parts[] = {
  CURLUPART_URL, CURLUPART_SCHEME, CURLUPART_USER, CURLUPART_PASSWORD,
  CURLUPART_OPTIONS, CURLUPART_HOST, CURLUPART_PORT, CURLUPART_PATH,
  CURLUPART_QUERY, CURLUPART_FRAGMENT, CURLUPART_ZONEID
};

static unsigned int uint_arg(const char *s)
{
  return (unsigned int)strtoul(s, NULL, 10);
}

static const char *nullable_arg(const char *s)
{
  return strcmp(s, "__NULL__") ? s : NULL;
}

static int hexval(char c)
{
  if(c >= '0' && c <= '9')
    return c - '0';
  if(c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if(c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static char *hex_arg(const char *s)
{
  size_t len;
  size_t i;
  char *out;
  if(!strcmp(s, "__NULL__"))
    return NULL;
  if(!strcmp(s, "__EMPTY_HANDLE__")) {
    out = malloc(17);
    if(out)
      memcpy(out, "__EMPTY_HANDLE__", 17);
    return out;
  }
  len = strlen(s);
  if(len % 2)
    return NULL;
  out = malloc(len / 2 + 1);
  if(!out)
    return NULL;
  for(i = 0; i < len; i += 2) {
    int hi = hexval(s[i]);
    int lo = hexval(s[i + 1]);
    if(hi < 0 || lo < 0) {
      free(out);
      return NULL;
    }
    out[i / 2] = (char)((hi << 4) | lo);
  }
  out[len / 2] = '\0';
  return out;
}

static CURLUPart part_arg(const char *s)
{
  size_t i;
  for(i = 0; i < sizeof(json_part_names) / sizeof(json_part_names[0]); i++) {
    if(!strcmp(s, json_part_names[i]))
      return curl_parts[i];
  }
  return CURLUPART_URL;
}

static void json_string(const char *s)
{
  const unsigned char *p = (const unsigned char *)s;
  putchar('"');
  for(; p && *p; p++) {
    switch(*p) {
    case '\\': fputs("\\\\", stdout); break;
    case '"': fputs("\\\"", stdout); break;
    case '\b': fputs("\\b", stdout); break;
    case '\f': fputs("\\f", stdout); break;
    case '\n': fputs("\\n", stdout); break;
    case '\r': fputs("\\r", stdout); break;
    case '\t': fputs("\\t", stdout); break;
    default:
      if(*p < 0x20)
        printf("\\u%04x", *p);
      else
        putchar(*p);
    }
  }
  putchar('"');
}

static void code_field(const char *name, CURLUcode code)
{
  printf("\"%s_code\":%d,\"%s_error\":", name, (int)code, name);
  json_string(curl_url_strerror(code));
}

static void emit_part(CURLU *h, CURLUPart part, const char *name,
                      unsigned int flags)
{
  char *value = NULL;
  CURLUcode rc = curl_url_get(h, part, &value, flags);
  putchar('"');
  fputs(name, stdout);
  fputs("\":{\"code\":", stdout);
  printf("%d", (int)rc);
  fputs(",\"error\":", stdout);
  json_string(curl_url_strerror(rc));
  fputs(",\"value\":", stdout);
  if(!rc && value)
    json_string(value);
  else
    fputs("null", stdout);
  putchar('}');
  curl_free(value);
}

static void emit_parts(CURLU *h, unsigned int flags)
{
  size_t i;
  fputs("\"parts\":{", stdout);
  for(i = 0; i < sizeof(json_part_names) / sizeof(json_part_names[0]); i++) {
    if(i)
      putchar(',');
    emit_part(h, curl_parts[i], json_part_names[i], flags);
  }
  putchar('}');
}

static void op_parse(int argc, char **argv)
{
  CURLU *h = curl_url();
  CURLUcode rc = curl_url_set(h, CURLUPART_URL, nullable_arg(argv[2]),
                              uint_arg(argv[3]));
  unsigned int get_flags = uint_arg(argv[4]);
  putchar('{');
  code_field("set", rc);
  if(!rc) {
    putchar(',');
    emit_parts(h, get_flags);
  }
  putchar('}');
  curl_url_cleanup(h);
  (void)argc;
}

static void op_parse_hex(int argc, char **argv)
{
  char *url = hex_arg(argv[2]);
  CURLU *h = curl_url();
  CURLUcode rc = curl_url_set(h, CURLUPART_URL, url, uint_arg(argv[3]));
  unsigned int get_flags = uint_arg(argv[4]);
  putchar('{');
  code_field("set", rc);
  if(!rc) {
    putchar(',');
    emit_parts(h, get_flags);
  }
  putchar('}');
  curl_url_cleanup(h);
  free(url);
  (void)argc;
}

static void op_getpart(int argc, char **argv)
{
  CURLU *h = curl_url();
  CURLUcode rc = curl_url_set(h, CURLUPART_URL, nullable_arg(argv[2]),
                              uint_arg(argv[3]));
  unsigned int get_flags = uint_arg(argv[5]);
  putchar('{');
  code_field("set", rc);
  if(!rc) {
    putchar(',');
    emit_part(h, part_arg(argv[4]), "part", get_flags);
  }
  putchar('}');
  curl_url_cleanup(h);
  (void)argc;
}

static void op_setpart(int argc, char **argv)
{
  CURLU *h = curl_url();
  CURLUcode init = CURLUE_OK;
  CURLUcode setrc;
  unsigned int get_flags = uint_arg(argv[7]);
  if(strcmp(argv[2], "__EMPTY_HANDLE__"))
    init = curl_url_set(h, CURLUPART_URL, nullable_arg(argv[2]),
                        uint_arg(argv[3]));
  setrc = curl_url_set(h, part_arg(argv[4]), nullable_arg(argv[5]),
                       uint_arg(argv[6]));
  putchar('{');
  code_field("init", init);
  putchar(',');
  code_field("set", setrc);
  if(!init) {
    putchar(',');
    emit_parts(h, get_flags);
  }
  putchar('}');
  curl_url_cleanup(h);
  (void)argc;
}

static void op_setpart_hex(int argc, char **argv)
{
  char *base = hex_arg(argv[2]);
  char *value = hex_arg(argv[5]);
  CURLU *h = curl_url();
  CURLUcode init = CURLUE_OK;
  CURLUcode setrc;
  unsigned int get_flags = uint_arg(argv[7]);
  if(!base || strcmp(base, "__EMPTY_HANDLE__"))
    init = curl_url_set(h, CURLUPART_URL, base, uint_arg(argv[3]));
  setrc = curl_url_set(h, part_arg(argv[4]), value, uint_arg(argv[6]));
  putchar('{');
  code_field("init", init);
  putchar(',');
  code_field("set", setrc);
  if(!init) {
    putchar(',');
    emit_parts(h, get_flags);
  }
  putchar('}');
  curl_url_cleanup(h);
  free(base);
  free(value);
  (void)argc;
}

static void op_relative(int argc, char **argv)
{
  CURLU *h = curl_url();
  CURLUcode base = curl_url_set(h, CURLUPART_URL, nullable_arg(argv[2]),
                                uint_arg(argv[3]));
  CURLUcode rel = curl_url_set(h, CURLUPART_URL, nullable_arg(argv[4]),
                               uint_arg(argv[5]));
  unsigned int get_flags = uint_arg(argv[6]);
  putchar('{');
  code_field("base", base);
  putchar(',');
  code_field("relative", rel);
  if(!base && !rel) {
    putchar(',');
    emit_parts(h, get_flags);
  }
  putchar('}');
  curl_url_cleanup(h);
  (void)argc;
}

static void op_relative_hex(int argc, char **argv)
{
  char *base_url = hex_arg(argv[2]);
  char *relative_url = hex_arg(argv[4]);
  CURLU *h = curl_url();
  CURLUcode base = curl_url_set(h, CURLUPART_URL, base_url, uint_arg(argv[3]));
  CURLUcode rel = curl_url_set(h, CURLUPART_URL, relative_url, uint_arg(argv[5]));
  unsigned int get_flags = uint_arg(argv[6]);
  putchar('{');
  code_field("base", base);
  putchar(',');
  code_field("relative", rel);
  if(!base && !rel) {
    putchar(',');
    emit_parts(h, get_flags);
  }
  putchar('}');
  curl_url_cleanup(h);
  free(base_url);
  free(relative_url);
  (void)argc;
}

static void op_dup(int argc, char **argv)
{
  CURLU *h = curl_url();
  CURLU *d = NULL;
  char *original = NULL;
  char *duplicate = NULL;
  CURLUcode init = curl_url_set(h, CURLUPART_URL, argv[2], uint_arg(argv[3]));
  CURLUcode setrc = CURLUE_BAD_HANDLE;
  CURLUcode orc = CURLUE_BAD_HANDLE;
  CURLUcode drc = CURLUE_BAD_HANDLE;
  if(!init) {
    d = curl_url_dup(h);
    if(d)
      setrc = curl_url_set(d, part_arg(argv[4]), nullable_arg(argv[5]),
                           uint_arg(argv[6]));
    orc = curl_url_get(h, CURLUPART_URL, &original, uint_arg(argv[7]));
    if(d)
      drc = curl_url_get(d, CURLUPART_URL, &duplicate, uint_arg(argv[7]));
  }
  putchar('{');
  code_field("init", init);
  putchar(',');
  code_field("dup_set", setrc);
  fputs(",\"original\":{\"code\":", stdout);
  printf("%d", (int)orc);
  fputs(",\"value\":", stdout);
  if(!orc && original)
    json_string(original);
  else
    fputs("null", stdout);
  fputs("},\"duplicate\":{\"code\":", stdout);
  printf("%d", (int)drc);
  fputs(",\"value\":", stdout);
  if(!drc && duplicate)
    json_string(duplicate);
  else
    fputs("null", stdout);
  fputs("}}", stdout);
  curl_free(original);
  curl_free(duplicate);
  curl_url_cleanup(d);
  curl_url_cleanup(h);
  (void)argc;
}

static void op_strerror(int argc, char **argv)
{
  int code = atoi(argv[2]);
  fputs("{\"message\":", stdout);
  json_string(curl_url_strerror((CURLUcode)code));
  putchar('}');
  (void)argc;
}

static void op_cleanup_null(void)
{
  curl_url_cleanup(NULL);
  fputs("{\"ok\":true}", stdout);
}

int main(int argc, char **argv)
{
  if(argc < 2) {
    fputs("{\"error\":\"missing op\"}", stdout);
    return 2;
  }
  if(!strcmp(argv[1], "parse") && argc == 5)
    op_parse(argc, argv);
  else if(!strcmp(argv[1], "parse_hex") && argc == 5)
    op_parse_hex(argc, argv);
  else if(!strcmp(argv[1], "getpart") && argc == 6)
    op_getpart(argc, argv);
  else if(!strcmp(argv[1], "setpart") && argc == 8)
    op_setpart(argc, argv);
  else if(!strcmp(argv[1], "setpart_hex") && argc == 8)
    op_setpart_hex(argc, argv);
  else if(!strcmp(argv[1], "relative") && argc == 7)
    op_relative(argc, argv);
  else if(!strcmp(argv[1], "relative_hex") && argc == 7)
    op_relative_hex(argc, argv);
  else if(!strcmp(argv[1], "dup") && argc == 8)
    op_dup(argc, argv);
  else if(!strcmp(argv[1], "strerror") && argc == 3)
    op_strerror(argc, argv);
  else if(!strcmp(argv[1], "cleanup_null") && argc == 2)
    op_cleanup_null();
  else {
    fputs("{\"error\":\"bad arguments\"}", stdout);
    return 2;
  }
  putchar('\n');
  return 0;
}
