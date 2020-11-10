<h2 style="background: #9999ee;font-size:45;font-weigth:400;">AES加密流程</h2>

## **定义结构体**

```c
typedef int uint8_t;//定义别名
typedef struct plain{
	uint8_t text[16];//存放明文
	uint8_t key[14][16];//存放10个扩展密钥+1个初始密钥
}Plain;
Plain plain;//全局明文+秘钥
```

## **明文输入（plaintext）**
```c
//--------------plaintext----------
void plain_str_uint8(Plain &plain){
/*%2lx  -表示两个两个读入*/
	int i;
	printf("please input a serises of 16bytes-plaintext:\n");
	for(i = 0 ;i < 16; i++)scanf("%2lx",&plain.text[i]);//每次读取两个16进制字符表示一个8bit字节
	printf("please input a serises of 16bytes-keytext:\n");
	for(i = 0 ;i < 16; i++)scanf("%2lx",&plain.key[0][i]);//每次读取两个16进制字符表示一个8bit字节
}
```

## 圈密钥加（addkey）

| 圈数 | 密钥长度 |
| :--: | :------: |
|  10  |   128    |
|  12  |   192    |
|  14  |   256    |

```
//--------------圈秘钥加-----------
void Addkey(Plain &plain,int round_num){
	int i;
	for (i = 0; i < 16; i++){
		plain.text[i] ^= plain.key[round_num][i];//明文密钥对应位相异或
	}
	//display(Roundkey,round_num);//显示数据
}
```

## 密钥扩展算法

```c
//---------------圈秘钥生成-----------------
/*轮常量表 The key schedule rcon table*/
uint8_t Rcon[10]={
	0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};
//---------------秘钥生成算法---------------
//左移一位
void Rotbyte(uint8_t key[])
{
	int a;
	a=key[0];	key[0]=key[1];	key[1]=key[2];	key[2]=key[3];	key[3]=a;
}
//秘钥扩展
void KeyExpansion(Plain &plain){
	/*按找是否为4的倍数分为两种情况
	$val:
		Nr--圈数
		Nk--字数
	*/
	int i,j;uint8_t key[4];
	for (i = 4;i < 44;i++)
	{	
		
		if(i%4 == 0){//先移位，再做字节代替，最后与轮常量异或，这里表示有点繁杂，希望读者耐心分析
			for (j = 0;j < 4;j++)key[j] = plain.key[(int)((i/4)-1)][12+j];
			Rotbyte(key);
			for (j = 1;j < 4;j++)plain.key[(int)(i/4)][j] = Sbox_byte(key[j])
				^(plain.key[(int)(i/4)-1][j]);
			plain.key[(int)(i/4)][0] = Sbox_byte(key[0])
				^(plain.key[(int)(i/4)-1][0])^Rcon[(int)(i/4)-1];
			
		}else{
			
			for (j = 0;j < 4;j++)plain.key[(int)(i/4)][4*(i%4)+j] = 
				plain.key[(int)((i-1)/4)][4*((i-1)%4)+j]^plain.key[(int)((i-4)/4)][4*((i-4)%4)+j];
		}	
	}

}
```

## S盒代替（s_box)

```c
/*该部分为S盒生成部分，生成过程有些难理解，读者也可直接应用已知的S盒直接列出*/
uint8_t polynomialMutil(uint8_t a, uint8_t b)
{
	/*多项式乘法
	$val:
		-a:
		-b:
		-tmp:
	$return:
		-tmp[0]:
	*/
    uint8_t tmp[8]={0};
    uint8_t i;
	//tmp[0] = tmp[0] ^ tmp[1] ^ tmp[2] ^ tmp[3] ^ tmp[4] ^ tmp[5] ^ tmp[6] ^ tmp[7];
    for(i=0;i<8;i++)
    {
        tmp[0] ^= (a<<i)*((b>>i)&0x1);
    }
    return tmp[0];
}

uint8_t findHigherBit(uint8_t val)
{
	/*
	$val:
		-counter:计数器
	$return:
		最高位
	*/
    int counter=0;
    while(val>>counter++);
    return counter;
}
//GF(2^8)的多项式除法
uint8_t gf28_div(uint8_t div_ed, uint8_t div, uint8_t *remainder)
{
    uint8_t r0=0; 
    uint8_t  qn=0;
    int bitCnt=0;

    r0=div_ed;

    bitCnt = findHigherBit(r0)-findHigherBit(div);
    while(bitCnt>=0)
    {
        qn = qn | (1<<bitCnt);
        r0 = r0 ^ (div<<bitCnt);
        bitCnt = findHigherBit(r0)-findHigherBit(div);
    }
    *remainder = r0;
    return qn;
}

//GF(2^8)多项式的扩展欧几里得算法
uint8_t extEuclidPolynomial(uint8_t a, uint8_t m)
{
    uint8_t r0, r1, r2 ,qn, v0, v1, v2, w0, w1, w2;
    r0=m;r1=a;
    v0=1;v1=0;
    w0=0;w1=1;
    while(r1!=1)
    {
        qn=gf28_div(r0, r1, &r2);

        v2=v0^polynomialMutil(qn, v1);
        w2=w0^polynomialMutil(qn, w1);

        r0=r1;r1=r2;
        v0=v1;v1=v2;

        w0=w1;w1=w2;
    }
    return w1;
}
//S盒字节变换
uint8_t byteTransformation(uint8_t a, uint8_t x)
{
    uint8_t tmp[8]={0};
	//tmp[0] = tmp[0]+tmp[1]+tmp[2]+tmp[3]+tmp[4]+tmp[5]+tmp[6]+tmp[7];
    for(uint8_t i=0;i<8;i++)
    {
        tmp[0] += (((a>>i)&0x1)^((a>>((i+4)%8))&0x1)^((a>>((i+5)%8))&0x1)^((a>>((i+6)%8))&0x1)^((a>>((i+7)%8))&0x1)^((x>>i)&0x1)) << i;
    } 
    return tmp[0];
}

//逆S盒字节变换
uint8_t invByteTransformation(uint8_t a, uint8_t x)
{
    uint8_t tmp[8]={0};
	//tmp[0] = tmp[0]+tmp[1]+tmp[2]+tmp[3]+tmp[4]+tmp[5]+tmp[6]+tmp[7];
    for(uint8_t i=0;i<8;i++)
    {
        tmp[0] += (((a>>((i+2)%8))&0x1)^((a>>((i+5)%8))&0x1)^((a>>((i+7)%8))&0x1)^((x>>i)&0x1)) << i;
    }
    return tmp[0];
}
//S盒产生
void s_box(Plain &plain){
	int i;
	for (i = 0;i < 16;i++)
		if (plain.text[i] != 0)
			plain.text[i] = byteTransformation(extEuclidPolynomial(plain.text[i],0x11B),0x63);
		else plain.text[i] = 0x63;
	//display(S_box);
}
//S盒单字节变化
uint8_t Sbox_byte(uint8_t d){
	if(d != 0)return byteTransformation(extEuclidPolynomial(d,0x11B),0x63);
	return 0x63;
}
```

## 行移位（shiftrows）

<font color=#A52A2A size=5 >矩阵均如下表样式排序</font>

序号|0 | 1 | 2 | 3
:--: | :--: | :--: | :--: | :--:
0|A<sub>0</sub>|A<sub>4</sub>|A<sub>8</sub>|A<sub>12</sub>
1|A<sub>1</sub>|A<sub>5</sub>|A<sub>9</sub>|A<sub>13</sub>
2|A<sub>2</sub>|A<sub>6</sub>|A<sub>10</sub>|A<sub>14</sub>
3|A<sub>3</sub>|A<sub>7</sub>|A<sub>11</sub>|A<sub>15</sub>
```c
//--------------------行移位-----------------------
void swap(uint8_t *a,uint8_t *b){//交换变量
	int tmp;
	tmp = *a;*a = *b;*b = tmp;
}
void ShiftRows(Plain &plain){

	int tmp;//暂存容器
	//layer-2
	tmp = plain.text[1];			plain.text[1] = plain.text[5];
	plain.text[5] = plain.text[9];	plain.text[9] = plain.text[13];
	plain.text[13] = tmp;
	//layer-3
	swap(&plain.text[2],&plain.text[10]);swap(&plain.text[6],&plain.text[14]);
	//layer-4
	tmp = plain.text[15];				plain.text[15] = plain.text[11];
	plain.text[11] = plain.text[7];		plain.text[7] = plain.text[3];
	plain.text[3] = tmp;
	//display(Shiftrows);
}

```

## **列混合（mixcolumns）**

多项式 | 二进制  | 十六进制 | x乘
-- | -- | -- | --
x | 0010 | 0x2 |  x2time(x)
x+1 | 0011 | 0x3 | x2time(x)^x
x<sup>2</sup>|0100 | 0x4 | x2time(x2time(x))
x<sup>3</sup>|1000 | 0x8 | x2time(x2time(x2time(x))) 
x<sup>3</sup>+1|1001 | 0x9 | x2time(x2time(x2time(x)))^x 
x<sup>3</sup>+x+1|1011 | 0xb | x2time(x2time(x2time(x)))^x2time(x)^x
x<sup>3</sup>+x<sup>2</sup>+1|1101 | 0xd | x2time(x2time(x2time(x)))^x2time(x2time(x))^x 
x<sup>3</sup>+x<sup>2</sup>+x|1110 | 0xe | x2time(x2time(x2time(x)))^x2time(x2time(x))^x2time(x)
以上为列混合及逆列混合时需要用到的


序号|0 | 1 | 2 | 3
:--: | :--: | :--: | :--: | :--:
0|02|03|01|01
1|03|01|01|02
2|01|01|02|03
3|01|02|03|01
**列混合矩阵**

```c
//--------------------列混合-----------------------
uint8_t x2time(uint8_t x)//x乘表示多项式与x相乘
{
	if (x&0x80)
	{
		return (((x<<1)^0x1B)&0xFF);
	}
	return x<<1;
}
uint8_t xtime(uint8_t num,uint8_t x){
	switch(num){
	case 0x2:return  x2time(x);//10   ->   x
	case 0x3:return (x2time(x)^x);//11  -> x<sup>2</sup>+x
	case 0x4:return ( x2time(x2time(x)) );
	case 0x8:return ( x2time(x2time(x2time(x))) );
	case 0x9:return ( x2time(x2time(x2time(x)))^x );
	case 0xb:return ( x2time(x2time(x2time(x)))^x2time(x)^x );
	case 0xd:return ( x2time(x2time(x2time(x)))^x2time(x2time(x))^x );
	case 0xe:return ( x2time(x2time(x2time(x)))^x2time(x2time(x))^x2time(x) );
	default:return 0;
	}
}
//列混合
void MixColumns(Plain &plain){
	uint8_t tmp[4];
	int i;
	for(i=0;i<4;i++) 
	{
		tmp[0]=xtime(0x2,plain.text[0+4*i])^xtime(0x3,plain.text[1+4*i])^plain.text[2+4*i]^plain.text[3+4*i];
		tmp[1]=xtime(0x2,plain.text[1+4*i])^xtime(0x3,plain.text[2+4*i])^plain.text[3+4*i]^plain.text[0+4*i];
		tmp[2]=xtime(0x2,plain.text[2+4*i])^xtime(0x3,plain.text[3+4*i])^plain.text[0+4*i]^plain.text[1+4*i];
		tmp[3]=xtime(0x2,plain.text[3+4*i])^xtime(0x3,plain.text[0+4*i])^plain.text[1+4*i]^plain.text[2+4*i];
		plain.text[0+4*i]=tmp[0];	plain.text[1+4*i]=tmp[1];
		plain.text[2+4*i]=tmp[2];	plain.text[3+4*i]=tmp[3];
	}
	//display(Mixcolumns);
}

```
## **AES加密**
```c
//AES加密算法
void AES_Encrypt(Plain &plain){
	int i;
	KeyExpansion(plain);
	Addkey(plain,0);
	for (i = 1;i <= 9;i++)
	{
		s_box(plain);
		ShiftRows(plain);
		MixColumns(plain);
		Addkey(plain,i);
	}
	s_box(plain);
	ShiftRows(plain);
	Addkey(plain,10);
}
```
<h2 style="background: #9999ee;font-size:45;font-weigth:400;">AES解密流程</h2>

## **秘钥逆扩展**
```c
//秘钥逆扩展
void inv_KeyExpansion(Plain &plain){
	/*
	$val:
		Nr--圈数
		Nk--字数
	*/
	int i,j;uint8_t tmp[4];
	for(j=1;j<=9;j++)
	for(i=0;i<4;i++) 
	{
		tmp[0]=xtime(0xe,plain.key[j][0+4*i])^xtime(0xb,plain.key[j][1+4*i])^xtime(0xd,plain.key[j][2+4*i])^xtime(0x9,plain.key[j][3+4*i]);
		tmp[1]=xtime(0xe,plain.key[j][1+4*i])^xtime(0xb,plain.key[j][2+4*i])^xtime(0xd,plain.key[j][3+4*i])^xtime(0x9,plain.key[j][0+4*i]);
		tmp[2]=xtime(0xe,plain.key[j][2+4*i])^xtime(0xb,plain.key[j][3+4*i])^xtime(0xd,plain.key[j][0+4*i])^xtime(0x9,plain.key[j][1+4*i]);
		tmp[3]=xtime(0xe,plain.key[j][3+4*i])^xtime(0xb,plain.key[j][0+4*i])^xtime(0xd,plain.key[j][1+4*i])^xtime(0x9,plain.key[j][2+4*i]);
		plain.key[j][0+4*i]=tmp[0];	plain.key[j][1+4*i]=tmp[1];
		plain.key[j][2+4*i]=tmp[2];	plain.key[j][3+4*i]=tmp[3];
	}

}
```
## **逆S盒产生**
```c
//逆S盒产生
void inv_s_box(Plain &plain){
	int i;
	for (i = 0;i < 16;i++)
		if (plain.text[i] != 0x63)
			plain.text[i] = extEuclidPolynomial(invByteTransformation(plain.text[i],0x05),0x11B);
		else plain.text[i] = 0x0;
	display(inv_S_box);
}
```
## **逆行移位**
```c
void inv_ShiftRows(Plain &plain){
	int tmp;//暂存容器
	//layer-2
	tmp = plain.text[13];			plain.text[13] = plain.text[9];
	plain.text[9] = plain.text[5];	plain.text[5] = plain.text[1];
	plain.text[1] = tmp;
	//layer-3
	swap(&plain.text[2],&plain.text[10]);swap(&plain.text[6],&plain.text[14]);
	//layer-4
	tmp = plain.text[3];				plain.text[3] = plain.text[7];
	plain.text[7] = plain.text[11];		plain.text[11] = plain.text[15];
	plain.text[15] = tmp;
	display(inv_Shiftrows);
}
```
## **逆列混合**



序号|0 | 1 | 2 | 3
:--: | :--: | :--: | :--: | :--:
0|0e|0b|0d|09
1|0b|0d|09|0e
2|0d|09|0e|0b
3|09|0e|0b|0d
**逆列混合矩阵**

```c
//逆列混合
void inv_MixColumns(Plain &plain){
	uint8_t tmp[4];
	int i;
	for(i=0;i<4;i++) 
	{
		tmp[0]=xtime(0xe,plain.text[0+4*i])^xtime(0xb,plain.text[1+4*i])^xtime(0xd,plain.text[2+4*i])^xtime(0x9,plain.text[3+4*i]);
		tmp[1]=xtime(0xe,plain.text[1+4*i])^xtime(0xb,plain.text[2+4*i])^xtime(0xd,plain.text[3+4*i])^xtime(0x9,plain.text[0+4*i]);
		tmp[2]=xtime(0xe,plain.text[2+4*i])^xtime(0xb,plain.text[3+4*i])^xtime(0xd,plain.text[0+4*i])^xtime(0x9,plain.text[1+4*i]);
		tmp[3]=xtime(0xe,plain.text[3+4*i])^xtime(0xb,plain.text[0+4*i])^xtime(0xd,plain.text[1+4*i])^xtime(0x9,plain.text[2+4*i]);
		plain.text[0+4*i]=tmp[0];	plain.text[1+4*i]=tmp[1];
		plain.text[2+4*i]=tmp[2];	plain.text[3+4*i]=tmp[3];
	}

}
```
## **AES解密算法**
```c
//AES解密算法
void AES_Decrypt(Plain &plain){
	int i;
	inv_KeyExpansion(plain);
	Addkey(plain,10);
	for (i = 9;i >= 1;i--)
	{
		inv_s_box(plain);
		inv_ShiftRows(plain);
		inv_MixColumns(plain);
		Addkey(plain,i);	
	}
	inv_s_box(plain);
	inv_ShiftRows(plain);
	Addkey(plain,0);
}
```
<h2 style="background: #9999ee;font-size:45;font-weigth:400;">数据展示</h2>

```c
enum text{ Encrypted_text,Decrypted_text,Roundkey,S_box,Shiftrows,Mixcolumns,
inv_S_box,inv_Shiftrows,inv_Mixcolumns
};
//----------------print()----------------------
/*数据展示*/
void print_begin(){
	printf("---------*-AES_EN_DE_crypt_TEST-*---------\n");
	printf("PS:format>>>\n");
	printf(">please input a serises of 16bytes-plaintext:\n");
	printf(">3243f6a8885a308d313198a2e0370734\n");
	printf(">please input a serises of 16bytes-keytext:  \n");
	printf(">2b7e151628aed2a6abf7158809cf4f3c\n");
	printf("OK!That's all.\n");
	printf("------------------------------------------\n");
}
void _print(int length){
	int i;
	for(i = 0;i < 16;i++)printf("| %02lx ",plain.text[i]);printf("|");
	printf("\n%-*s",length,"");for(i = 0;i < 81;i++)printf("%c",'+');
}
void display(int name,int round = 0){//密文输出
	int i;
	switch(name){
		case 0:{
			printf("\n%-35s","");for(i = 0;i < 81;i++)printf("%c",'-');
			printf("\n%-35s","The 16-bytes Encrypted-text is : ");
			_print(35);break;
		}
		case 1:{
			printf("\n%-35s","");for(i = 0;i < 81;i++)printf("%c",'-');
			printf("\n%-35s","The 16-bytes Decrypted-text is : ");
			_print(35);printf("\n");break;
		}
		case 2:{
			printf("\n%The %2d-th Round_key is : ",round+1);
			for(i = 0;i < 16;i++)printf("| %02lx ",plain.key[round][i]);printf("|");
			printf("\n%-25s","");for(i = 0;i < 81;i++)printf("%c",'+');break;
		}
		case 3:{
			printf("\n%-25s","S_boxed is : ");
			_print(25);break;
		}
		case 4:{
			printf("\n%-25s","ShiftRowed is : ");
			_print(25);break;
		}
		case 5:{
			printf("\n%-25s","Mixcolumned is : ");
			_print(25);break;
		}
		case 6:{
			printf("\n%-25s","inv_S_boxed is : ");
			_print(25);break;
		}
		case 7:{
			printf("\n%-25s","inv_Shiftrowed is : ");
			_print(25);break;
		}
		case 8:{
			printf("\n%-25s","inv_Mixcolumned is : ");
			_print(25);break;
		}

	}
	
}

```
<h2 style="background: #9999ee;font-size:45;font-weigth:400;">主体实现</h2>

```c
int main(){
	//double first,last;
	print_begin();
	plain_str_uint8(plain);
	//first = clock();
	AES_Encrypt(plain);
	//last = clock();
	//printf("\nctime = \n%lf\n",first-last);
	display(Encrypted_text);
	printf("\n");
	AES_Decrypt(plain);
	display(Decrypted_text);
	return 0;
}
```

<h2 style="background: #9999ee;">图片展示</h2>

<img src="pic/1.png" width = "1000" height = "540" alt="图片名称" 
align=center>

<h2 style="background: #aaaaee;font-size:45;font-weigth:400;">输入明文秘钥及中间步骤所有加解密过程</h2>

- 输入明文实例 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
- 输入秘钥实例 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
- 密文39  25  84  1d  02  dc  09  fb  dc  11  85  97  19  6a  0b  32 

| list | 1    | 2    | 3    | 4    | 5    | 6    | 7    | 8    | 9    | 10   | 11   | 12   | 13   | 14   | 15   | 16   |
| :---: | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- |
The 16-bytes plain-text is :   | 32 | 43 | f6 | a8 | 88 | 5a | 30 | 8d | 31 | 31 | 98 | a2 | e0 | 37 | 07 | 34 |
The 16-bytes key-text is :   | 2b | 7e | 15 | 16 | 28 | ae | d2 | a6 | ab | f7 | 15 | 88 | 09 | cf | 4f | 3c |
The 16-bytes Encrypted-text is :   | 39 | 25 | 84 | 1d | 02 | dc | 09 | fb | dc | 11 | 85 | 97 | 19 | 6a | 0b | 32 |
The 16-bytes Decrypted-text is :   | 32 | 43 | f6 | a8 | 88 | 5a | 30 | 8d | 31 | 31 | 98 | a2 | e0 | 37 | 07 | 34 |
The  1-th Round_key is : | 2b | 7e | 15 | 16 | 28 | ae | d2 | a6 | ab | f7 | 15 | 88 | 09 | cf | 4f | 3c |
S_boxed is :             | d4 | 27 | 11 | ae | e0 | bf | 98 | f1 | b8 | b4 | 5d | e5 | 1e | 41 | 52 | 30 |
ShiftRowed is :          | d4 | bf | 5d | 30 | e0 | b4 | 52 | ae | b8 | 41 | 11 | f1 | 1e | 27 | 98 | e5 | Mixcolumned is :         | 04 | 66 | 81 | e5 | e0 | cb | 19 | 9a | 48 | f8 | d3 | 7a | 28 | 06 | 26 | 4c |
The  2-th Round_key is : | a0 | fa | fe | 17 | 88 | 54 | 2c | b1 | 23 | a3 | 39 | 39 | 2a | 6c | 76 | 05 | 
S_boxed is :             | 49 | de | d2 | 89 | 45 | db | 96 | f1 | 7f | 39 | 87 | 1a | 77 | 02 | 53 | 3b |
ShiftRowed is :          | 49 | db | 87 | 3b | 45 | 39 | 53 | 89 | 7f | 02 | d2 | f1 | 77 | de | 96 | 1a |
Mixcolumned is :         | 58 | 4d | ca | f1 | 1b | 4b | 5a | ac | db | e7 | ca | a8 | 1b | 6b | b0 | e5 | 
The  3-th Round_key is : | f2 | c2 | 95 | f2 | 7a | 96 | b9 | 43 | 59 | 35 | 80 | 7a | 73 | 59 | f6 | 7f | 
S_boxed is :             | ac | 73 | cf | 7b | ef | c1 | 11 | df | 13 | b5 | d6 | b5 | 45 | 23 | 5a | b8 | 
ShiftRowed is :          | ac | c1 | d6 | b8 | ef | b5 | 5a | 7b | 13 | 23 | cf | df | 45 | 73 | 11 | b5 |
Mixcolumned is :         | 75 | ec | 09 | 93 | 20 | 0b | 63 | 33 | 53 | c0 | cf | 7c | bb | 25 | d0 | dc |
The  4-th Round_key is : | 3d | 80 | 47 | 7d | 47 | 16 | fe | 3e | 1e | 23 | 7e | 44 | 6d | 7a | 88 | 3b | 
S_boxed is :             | 52 | 50 | 2f | 28 | 85 | a4 | 5e | d7 | e3 | 11 | c8 | 07 | f6 | cf | 6a | 94 | 
ShiftRowed is :          | 52 | a4 | c8 | 94 | 85 | 11 | 6a | 28 | e3 | cf | 2f | d7 | f6 | 50 | 5e | 07 |
Mixcolumned is :         | 0f | d6 | da | a9 | 60 | 31 | 38 | bf | 6f | c0 | 10 | 6b | 5e | b3 | 13 | 01 |
The  5-th Round_key is : | ef | 44 | a5 | 41 | a8 | 52 | 5b | 7f | b6 | 71 | 25 | 3b | db | 0b | ad | 00 |
S_boxed is :             | e1 | 4f | d2 | 9b | e8 | fb | fb | ba | 35 | c8 | 96 | 53 | 97 | 6c | ae | 7c |
ShiftRowed is :          | e1 | fb | 96 | 7c | e8 | c8 | ae | 9b | 35 | 6c | d2 | ba | 97 | 4f | fb | 53 |
Mixcolumned is :         | 25 | d1 | a9 | ad | bd | 11 | d1 | 68 | b6 | 3a | 33 | 8e | 4c | 4c | c0 | b0 | 
The  6-th Round_key is : | d4 | d1 | c6 | f8 | 7c | 83 | 9d | 87 | ca | f2 | b8 | bc | 11 | f9 | 15 | bc |
S_boxed is :             | a1 | 63 | a8 | fc | 78 | 4f | 29 | df | 10 | e8 | 3d | 23 | 4c | d5 | 03 | fe | 
ShiftRowed is :          | a1 | 4f | 3d | fe | 78 | e8 | 03 | fc | 10 | d5 | a8 | df | 4c | 63 | 29 | 23 | 
Mixcolumned is :         | 4b | 86 | 8d | 6d | 2c | 4a | 89 | 80 | 33 | 9d | f4 | e8 | 37 | d2 | 18 | d8 |
The  7-th Round_key is : | 6d | 88 | a3 | 7a | 11 | 0b | 3e | fd | db | f9 | 86 | 41 | ca | 00 | 93 | fd |
S_boxed is :             | f7 | ab | 31 | f0 | 27 | 83 | a9 | ff | 9b | 43 | 40 | d3 | 54 | b5 | 3d | 3f | 
ShiftRowed is :          | f7 | 83 | 40 | 3f | 27 | 43 | 3d | f0 | 9b | b5 | 31 | ff | 54 | ab | a9 | d3 | 
Mixcolumned is :         | 14 | 15 | b5 | bf | 46 | 16 | 15 | ec | 27 | 46 | 56 | d7 | 34 | 2a | d8 | 43 | 
The  8-th Round_key is : | 4e | 54 | f7 | 0e | 5f | 5f | c9 | f3 | 84 | a6 | 4f | b2 | 4e | a6 | dc | 4f | 
S_boxed is :             | be | 83 | 2c | c8 | d4 | 3b | 86 | c0 | 0a | e1 | d4 | 4d | da | 64 | f2 | fe | 
ShiftRowed is :          | be | 3b | d4 | fe | d4 | e1 | f2 | c8 | 0a | 64 | 2c | c0 | da | 83 | 86 | 4d |
Mixcolumned is :         | 00 | 51 | 2f | d1 | b1 | c8 | 89 | ff | 54 | 76 | 6d | cd | fa | 1b | 99 | ea | 
The  9-th Round_key is : | ea | d2 | 73 | 21 | b5 | 8d | ba | d2 | 31 | 2b | f5 | 60 | 7f | 8d | 29 | 2f |
S_boxed is :             | 87 | ec | 4a | 8c | f2 | 6e | c3 | d8 | 4d | 4c | 46 | 95 | 97 | 90 | e7 | a6 | 
ShiftRowed is :          | 87 | 6e | 46 | a6 | f2 | 4c | e7 | 8c | 4d | 90 | 4a | d8 | 97 | ec | c3 | 95 | 
Mixcolumned is :         | 47 | 37 | 94 | ed | 40 | d4 | e4 | a5 | a3 | 70 | 3a | a6 | 4c | 9f | 42 | bc |
The 10-th Round_key is : | ac | 77 | 66 | f3 | 19 | fa | dc | 21 | 28 | d1 | 29 | 41 | 57 | 5c | 00 | 6e | 
S_boxed is :             | e9 | 09 | 89 | 72 | cb | 31 | 07 | 5f | 3d | 32 | 7d | 94 | af | 2e | 2c | b5 |
ShiftRowed is :          | e9 | 31 | 7d | b5 | cb | 32 | 2c | 72 | 3d | 2e | 89 | 5f | af | 09 | 07 | 94 | 
The 11-th Round_key is : | d0 | 14 | f9 | a8 | c9 | ee | 25 | 89 | e1 | 3f | 0c | c8 | b6 | 63 | 0c | a6 | 
The 16-bytes Encrypted-text is :   | 39 | 25 | 84 | 1d | 02 | dc | 09 | fb | dc | 11 | 85 | 97 | 19 | 6a | 0b | 32 |
The 11-th Round_key is : | d0 | 14 | f9 | a8 | c9 | ee | 25 | 89 | e1 | 3f | 0c | c8 | b6 | 63 | 0c | a6 | 
inv_S_boxed is :         | eb | 2e | 13 | d2 | 59 | a1 | 42 | 1e | 8b | c3 | f2 | 84 | 1b | 40 | 38 | e7 | 
inv_Shiftrowed is :      | eb | 40 | f2 | 1e | 59 | 2e | 38 | 84 | 8b | a1 | 13 | e7 | 1b | c3 | 42 | d2 | 
The 10-th Round_key is : | 0c | 7b | 5a | 63 | 13 | 19 | ea | fe | b0 | 39 | 88 | 90 | 66 | 4c | fb | b4 |
inv_S_boxed is :         | ea | 45 | 98 | c5 | 04 | 5d | b0 | f0 | 65 | 96 | 5c | 2d | 85 | 83 | 33 | ad | 
inv_Shiftrowed is :      | ea | 83 | 5c | f0 | 04 | 45 | 33 | 2d | 65 | 5d | 98 | ad | 85 | 96 | b0 | c5 | 
The  9-th Round_key is : | df | 7d | 92 | 5a | 1f | 62 | b0 | 9d | a3 | 20 | 62 | 6e | d6 | 75 | 73 | 24 | 
inv_S_boxed is :         | 5a | 49 | 19 | 0c | 19 | e0 | 04 | b1 | a3 | 8c | 42 | 1f | 7a | 41 | dc | 65 | 
inv_Shiftrowed is :      | 5a | 41 | 42 | b1 | 19 | 49 | dc | 1f | a3 | e0 | 19 | 65 | 7a | 8c | 04 | 0c | 
The  8-th Round_key is : | 12 | c0 | 76 | 47 | c0 | 1f | 22 | c7 | bc | 42 | d2 | f3 | 75 | 55 | 11 | 4a |
inv_S_boxed is :         | 26 | 41 | 72 | 25 | 3d | 64 | 8b | 17 | e8 | d2 | 2e | 7d | fd | 0e | b7 | a9 |
inv_Shiftrowed is :      | 26 | 0e | 2e | 17 | 3d | 41 | b7 | 7d | e8 | 64 | 72 | a9 | fd | d2 | 8b | 25 | 
The  7-th Round_key is : | 6e | fc | d8 | 76 | d2 | df | 54 | 80 | 7c | 5d | f0 | 34 | c9 | 17 | c3 | b9 |
inv_S_boxed is :         | f1 | 92 | 8b | 0c | c1 | c8 | d5 | 55 | 7c | b5 | 6f | ef | 5d | 00 | 4c | 32 |
inv_Shiftrowed is :      | f1 | 00 | 6f | 55 | c1 | 92 | 4c | ef | 7c | c8 | 8b | 32 | 5d | b5 | d5 | 0c |
The  6-th Round_key is : | 6e | a3 | 0a | fc | bc | 23 | 8c | f6 | ae | 82 | a4 | b4 | b5 | 4a | 33 | 8d | 
inv_S_boxed is :         | e0 | 63 | 35 | 01 | c8 | b1 | be | e8 | d9 | b8 | 7f | c0 | 85 | 92 | 63 | 50 | 
inv_Shiftrowed is :      | e0 | 92 | 7f | e8 | c8 | 63 | 63 | c0 | d9 | b1 | 35 | 50 | 85 | b8 | be | 01 | 
The  5-th Round_key is : | 90 | 88 | 44 | 13 | d2 | 80 | 86 | 0a | 12 | a1 | 28 | 42 | 1b | c8 | 97 | 39 | 
inv_S_boxed is :         | 48 | 1d | b1 | e7 | 67 | e3 | 58 | ee | 4d | 5f | 4e | 0d | d6 | 6c | 9d | 38 |
inv_Shiftrowed is :      | 48 | 6c | 4e | ee | 67 | 1d | 9d | 0d | 4d | e3 | b1 | 38 | d6 | 5f | 58 | e7 |
The  4-th Round_key is : | 7c | 1f | 13 | f7 | 42 | 08 | c2 | 19 | c0 | 21 | ae | 48 | 09 | 69 | bf | 7b | 
inv_S_boxed is :         | aa | dd | 4a | 9a | 61 | d2 | 46 | 03 | 82 | 32 | 5f | ef | 68 | 8f | e3 | d2 | 
inv_Shiftrowed is :      | aa | 8f | 5f | 03 | 61 | dd | e3 | ef | 82 | d2 | 4a | d2 | 68 | 32 | 46 | 9a |
The  3-th Round_key is : | cc | 75 | 05 | eb | 3e | 17 | d1 | ee | 82 | 29 | 6c | 51 | c9 | 48 | 11 | 33 |
inv_S_boxed is :         | a4 | 9f | ea | 49 | 68 | 5b | 50 | f2 | 6b | 6a | 7f | 2b | 02 | 9c | 35 | 43 | 
inv_Shiftrowed is :      | a4 | 9c | 7f | f2 | 68 | 9f | 35 | 2b | 6b | 5b | ea | 43 | 02 | 6a | 50 | 49 |
The  2-th Round_key is : | 2b | 37 | 08 | a7 | f2 | 62 | d4 | 05 | bc | 3e | bd | bf | 4b | 61 | 7d | 62 |
inv_S_boxed is :         | 19 | f4 | 8d | 08 | a0 | c6 | 48 | be | 9a | f8 | e3 | 2b | e9 | 3d | e2 | 2a |
inv_Shiftrowed is :      | 19 | 3d | e3 | be | a0 | f4 | e2 | 2b | 9a | c6 | 8d | 2a | e9 | f8 | 48 | 08 |
The  1-th Round_key is : | 2b | 7e | 15 | 16 | 28 | ae | d2 | a6 | ab | f7 | 15 | 88 | 09 | cf | 4f | 3c |
The 16-bytes Decrypted-text is :   | 32 | 43 | f6 | a8 | 88 | 5a | 30 | 8d | 31 | 31 | 98 | a2 | e0 | 37 | 07 | 34 |