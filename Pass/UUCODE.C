
#define ccc2l(c,l)      (l =((unsigned long)(*((c)++)))<<16, \
			 l|=((unsigned long)(*((c)++)))<< 8, \
			 l|=((unsigned long)(*((c)++))))

#define l2ccc(l,c)      (*((c)++)=(unsigned char)(((l)>>16)&0xff), \
												 *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
												 *((c)++)=(unsigned char)(((l)    )&0xff))

int uuencode(in,num,out)
unsigned char *in;
int num;
unsigned char *out;
	{
	int j,i,k,n,tot=0;
	unsigned long l;
	register unsigned char *p;
	p=out;

	for (j=0; j<num; j+=45)
		{
		if (j+45 > num)
			i=(num-j);
		else	i=45;
		*(p++)=i+' ';
		for (n=0; n<i; n+=3)
			{
			ccc2l(in,l);
			*(p++)=((l>>18)&0x3f)+' ';
			*(p++)=((l>>12)&0x3f)+' ';
			*(p++)=((l>> 6)&0x3f)+' ';
			*(p++)=((l    )&0x3f)+' ';
			tot+=4;
			}
		*(p++)='\n';
		tot+=2;
		}
	*p='\0';
	l=0;
	return(tot);
	}

int uudecode(in,num,out)
unsigned char *in;
int num;
unsigned char *out;
	{
	int j,i,k;
	unsigned int n,space=0;
	unsigned long l;
	unsigned long w,x,y,z;
	unsigned int blank='\n'-' ';

	for (j=0; j<num; )
		{
		n= *(in++)-' ';
		if (n == blank)
			{
			n=0;
			in--;
			}
		if (n > 60)
			{
//			fprintf(stderr,"uuencoded line length too long\n");
			return(-1);
			}
		j++;

		for (i=0; i<n; j+=4,i+=3)
			{
			/* the following is for cases where spaces are
			 * removed from lines.
			 */
			if (space)
				{
				w=x=y=z=0;
				}
			else
				{
				w= *(in++)-' ';
				x= *(in++)-' ';
				y= *(in++)-' ';
				z= *(in++)-' ';
				}
			if ((w > 63) || (x > 63) || (y > 63) || (z > 63))
				{
				k=0;
				if (w == blank) k=1;
				if (x == blank) k=2;
				if (y == blank) k=3;
				if (z == blank) k=4;
				space=1;
				switch (k) {
				case 1:	w=0; in--;
				case 2: x=0; in--;
				case 3: y=0; in--;
				case 4: z=0; in--;
					break;
				case 0:
					space=0;
//					fprintf(stderr,"bad uuencoded data values\n");
					w=x=y=z=0;
					return(-1);
					break;
					}
				}
			l=(w<<18)|(x<<12)|(y<< 6)|(z    );
			l2ccc(l,out);
			}
		if (*(in++) != '\n')
			{
//			fprintf(stderr,"missing nl in uuencoded line\n");
			w=x=y=z=0;
			return(-1);
			}
		j++;
		}
	*out='\0';
	w=x=y=z=0;
	return(n);
	}
