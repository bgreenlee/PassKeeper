#ifndef PASSCRPT_HPP
#define PASSCRPT_HPP

class TCrypt {
	public:
		TCrypt();

		int encrypt(unsigned char */*data*/,unsigned int /*size*/, unsigned char */*password*/);
		int decrypt(unsigned char */*data*/,unsigned int /*size*/, unsigned char */*password*/);
};

#endif
