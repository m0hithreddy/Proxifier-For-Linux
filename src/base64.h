void decodeblock(unsigned char in[], char *clrstr);
void decodepass(char *b64src, char *clrdst);
void encodeblock( unsigned char in[], char b64str[], int len );
void encodepass(char *clrstr, char *b64dst);
