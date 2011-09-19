#ifndef _ADD_H_
#define _ADD_H_
	struct add{
		struct _add* true_add;
	};
	void initadd(struct add* ax);
	void printadd(struct add* ax);
	void closeadd(struct add* ax);
#endif
