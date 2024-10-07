---
title: "[Play with lua] Understand lua bytecode and fix luadec decompiler"
categories:
  - tool
  - program language
tags:
  - lua
  - tool
  - re
---

## TL;DR
Lua is often used for web service cgi in some kind of embedded devices. Most are version 5.1 and are modified. There are old tools but they are not stable. I got an error and it made me examined structure of lua bytecode and fixed luadec tool.

## Overview
Lua was developed a long time ago (1993) and I knew about it when auditting script on some embedded devices. Especially, it is developed as cgi (Common Gateway Interface) for web service. Because it is a lightweight high-level language, it is "more easy" to reversing. There are some tools for it like [unluac](https://sourceforge.net/projects/unluac), [luadec](https://github.com/viruscamp/luadec/), ... But all of them are stoped maintaining. Maybe it's cause reducing of community. I got some devices which use lua 5.1 or a modified version of it. I was tried out many tools to decompile (or just deassembly) Lua bytecode. Most times got success except the new one.

## Problem
Firstly, you should know that Openwrt lua bytecode is modified a little bit and some ones did [a research](http://web.archive.org/web/20190125113829/http://storypku.com/2015/07/how-to-decompile-bytecoded-openwrt-lua-files) about this. And we have [a difference version of luadec](https://github.com/HandsomeYingyan/luadec-openwrt). It was modified some opcode and structure of luabyte to became fit with Openwrt's modifies. When I tried decompile a lua bytecode file a week ago, I got an error on both versions of luadec tool:
```
./luadec: <...>.lua: bad header in precompiled chunk
```
Not suggest like usual @@. I started trace this error
### Frist solving
Check the sourcecode I knew that reason of error is 12 bytes of header is not matched:
```c
static void LoadHeader(LoadState* S)
{
 char h[LUAC_HEADERSIZE];
 char s[LUAC_HEADERSIZE];
 luaU_header(h);               // fixed header bytes of Luabytes code of 5.1
 LoadBlock(S,s,LUAC_HEADERSIZE); // get header bytes from file
 // I add new printHex
 printHex(h,LUAC_HEADERSIZE);   
 printHex(s,LUAC_HEADERSIZE);
 IF (memcmp(h,s,LUAC_HEADERSIZE)!=0, "bad header"); // error dump is from here
}
```
The "correct" header is generated depend on host's architecture and some fixed value. I knew, it is not fit with normal logic for a decompiler. Correct header should be depend on target's architecture:
```c
void luaU_header (char* h)
{
 int x=1;
 memcpy(h,LUA_SIGNATURE,sizeof(LUA_SIGNATURE)-1);
 h+=sizeof(LUA_SIGNATURE)-1;
 *h++=(char)LUAC_VERSION;
 *h++=(char)LUAC_FORMAT;
 *h++=(char)*(char*)&x;				/* endianness */
 *h++=(char)sizeof(int);
 *h++=(char)sizeof(unsigned int);
 *h++=(char)sizeof(Instruction);
 *h++=(char)sizeof(lua_Number);
 *h++=(char)(((lua_Number)0.5)==0);		/* is lua_Number integral? */
}
```
I also added some print to check what value is incorrect and read [document](https://gist.github.com/seanjensengrey/e198380afc64f0eb17a47512b48f040f) about Lua bytecode header. I chose solution is recompile it by crosscompiling on same architecture with my target. I knew it is st*pid way but I did not have much time to change from fix type variables to dynamic type variables in luadec sourcecode.
### Second solving
I still got same error after applying first solution. I checked bytes value again and relized a trouble with value of 12th byte:
```
000B  00                 integral (1=integral)
```
And this byte is `0x04` in my target bytecode file. I went around and saw Openwrt version has some differences at that position. You can see it more cleanly via source code. Boolean value of `lua_Number` integral become real value of `lua_Integer`'s length:
```c
 *h++=(char)sizeof(Instruction);
 *h++=(char)sizeof(lua_Number);

 *h++ = (char)(sizeof(lua_Integer)
#ifdef LNUM_COMPLEX
    | 0x80
#endif
    );
```
It means that my target belongs to a modified verion of Openwrt. But byte value of `lua_Number` was still different. Let's look deeper into sourcecode to examine how luadec set length of `lua_Number`:
```c
/* type of numbers in Lua */
typedef LUA_NUMBER lua_Number;
...
/*
** LUA_NUMBER is the type of floating point number in Lua
** LUA_NUMBER_SCAN is the format for reading numbers.
** LUA_NUMBER_FMT is the format for writing numbers.
*/
#ifdef LNUM_FLOAT
# define LUA_NUMBER         float
# define LUA_NUMBER_SCAN    "%f"
# define LUA_NUMBER_FMT     "%g"  
#elif (defined LNUM_DOUBLE)
# define LUA_NUMBER	        double
# define LUA_NUMBER_SCAN    "%lf"
# define LUA_NUMBER_FMT     "%.14g"
#elif (defined LNUM_LDOUBLE)
# define LUA_NUMBER         long double
# define LUA_NUMBER_SCAN    "%Lg"
# define LUA_NUMBER_FMT     "%.20Lg"
#endif
...
/*
** Default number modes
*/
#if (!defined LNUM_DOUBLE) && (!defined LNUM_FLOAT) && (!defined LNUM_LDOUBLE)
# define LNUM_DOUBLE
#endif
```
It means that `LUA_NUMBER` is set as `LNUM_DOUBLE` and some dependencies and it is `0x08`. But my target Lua bytecode file's header set it as `0x04`, I have to predefine `LNUM_FLOAT` compiler's variable to make that value become `0x04` and be same as my target.
### Third solving
Error is pop up again after above solving :\(, but this time is difference:
```
./luadec: <...>.lua: bad constant in precompiled chunk
```
What is this? Jump into source code again. Problem seems be from: `LoadFunction` -> `LoadConstants` and no type of constant is matched while extracting. You can discovery more about Lua constant via a [difference doc](https://docs.luaplusplus.org/language-improvements/constant-variables) but similar. The Lua constant type matching as follow code:
```c
  TValue* o=&f->k[i];
  int t=LoadChar(S);
  switch (t)
  {
   case LUA_TNIL:
   	setnilvalue(o);
	break;
   case LUA_TBOOLEAN:
   	setbvalue(o,LoadChar(S)!=0);
	break;
   case LUA_TNUMBER:
	setnvalue(o,LoadNumber(S));
	break;
   case LUA_TSTRING:
	setsvalue2n(S->L,o,LoadString(S));
	break;
   default:
	error(S,"bad constant");
	break;
  }
```
Seem like some type's value is not one of `LUA_TSTRING`, `LUA_TINT`, `LUA_TNUMBER`, `LUA_TBOOLEAN`, `LUA_TNIL`. Read [another blog](https://openpunk.com/pages/lua-bytecode-parser) to find some normal value of type 
![Constant type](/assets/images/2024-10-07-fixing-lua-decompiler/constants.png)
You also find more in luadec source code:
```c
#define LUA_TINT 9

#define LUA_TNIL		0
#define LUA_TBOOLEAN		1
#define LUA_TLIGHTUSERDATA	2
#define LUA_TNUMBER		3
#define LUA_TSTRING		4
#define LUA_TTABLE		5
#define LUA_TFUNCTION		6
#define LUA_TUSERDATA		7
#define LUA_TTHREAD		8
```
I added another `printHex` before matching code to check what value made error and got `0xfffffffe` (=254 because it is 1 byte). As getting a overview, I find another tool which is just extract Opcode  to raw value and I used [ulua script](https://github.com/bananabr/ulua) to do it.
As my prediction, there are many constants which havve `254` as type:
```
DECODING CONSTANTS (24)
00 {'TYPE': 4, 'DATA': 'mcf'}
...
08 {'TYPE': 254, 'DATA': 0}
...
```
But I realized more that having only type 4 and type 254 in my bytecode file. It means only String type and Unknow type :). I paied no attention to pre-comment above constant type defines but it was important when I went through again:
```c
/* LUA_TINT is an internal type, not visible to applications. There are three
 * potential values where it can be tweaked to (code autoadjusts to these):
 *
 * -2: not 'usual' type value; good since 'LUA_TINT' is not part of the API
 * LUA_TNUMBER+1: shifts other type values upwards, breaking binary compatibility
 *     not acceptable for 5.1, maybe 5.2 onwards?
 *  9: greater than existing (5.1) type values.
*/
```
My value is 254 (same as -2), so did I only change `LUA_TINT` from 9 to -2? No, luadec sourcecode have no handler for `LUA_TINT` type. There are 2 most popular types in program are number and string. Cause my `LUA_TINT` type should handling as number. But how many bytes for this type's value? I did some tests with `ulua` script and a 4 bytes number (as an int) is the most reasonable. Therefore, I added pieces of code:
```
--- lua-5.1/src/lundump.c
+++ lua-5.1/src/lundump.c
@@ static void LoadConstants(LoadState* S, Proto* f)
{
+  case LUA_TINT:   /* Integer type saved in bytecode (see lcode.c) */
+	setivalue(o,LoadInteger(S));
+	break;
}
--- a/luadec/proto.c
+++ b/luadec/proto.c
@@ -258,6 +258,12 @@ char* DecompileConstant(const Proto* f, int i) {
                return strdup(bvalue(o)?"true":"false");
        case LUA_TNIL:
                return strdup("nil");
+    case LUA_TINT:
+       {
+               char* ret = (char*)calloc(128, sizeof(char));
+               sprintf(ret, LUA_INTEGER_FMT, ivalue(o));
+               return ret;
+       }
```
Finnally, it worked !!
# P/S
I do not know why luadec is developed by strange way. It can not work independently and have to cross-compile with each target's arch. The sourcecode also has lacks of logic and processing. I want to develop a more perfect version of it but do not have much time now. Hope that I can it in near future.