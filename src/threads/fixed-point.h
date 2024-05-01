#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#define P_FIXED_POINT 17
#define Q_FIXED_POINT 14
#define F_FIXED_POINT (1<<(Q_FIXED_POINT))

static struct real {
    int value;
};

static struct real convert_int_to_real(int n);
static int convert_real_to_int_round_down(struct real x);
static int convert_real_to_int_round_nearest(struct real x);
static struct real add_real_to_real( struct real x, struct real y);
static struct real sub_real_from_real( struct real x, struct real y);
static struct real add_real_to_int(struct real x, int n);
static struct real sub_int_from_real (struct real x, int n);
static struct real multiply_real_by_real (struct real x, struct real y);
static struct real multiply_real_by_int(struct real x, int n);
static struct real divide_real_by_real(struct real x, struct real y);
static struct real divide_real_by_int(struct real x, int n);

static struct real convert_int_to_real(int n)
{
    struct real result;
	result.value=n * F_FIXED_POINT;
    return result;
}

static int convert_real_to_int_round_down(struct real x){
    return x.value/F_FIXED_POINT;
}

static int convert_real_to_int_round_nearest(struct real x){
    if (x.value>=0)
        return (x.value + F_FIXED_POINT / 2) / F_FIXED_POINT;
    else 
        return (x.value - F_FIXED_POINT / 2) / F_FIXED_POINT;
}
static struct real add_real_to_real( struct real x, struct real y){
    struct real result;
    result.value=x.value+y.value;
    return result;
}
static struct real sub_real_from_real( struct real x, struct real y){
    struct real result;
    result.value=x.value-y.value;
    return result;
}
static struct real add_real_to_int(struct real x, int n){
    struct real result;
    result.value=x.value + n * F_FIXED_POINT; // 0 + 1*(2^14)
    return result;
}

static struct real sub_int_from_real (struct real x, int n){
    struct real result;
    result.value=x.value - n * F_FIXED_POINT;
    return result;
}
static struct real multiply_real_by_real (struct real x, struct real y){
    struct real result;
    result.value = ((int64_t) x.value) * y.value / F_FIXED_POINT;
    return result;
}
static struct real multiply_real_by_int(struct real x, int n){
    struct real result;
    result.value = x.value*n;
    return result;
}
static struct real divide_real_by_real(struct real x, struct real y){
    struct real result;
    result.value=((int64_t) x.value) * F_FIXED_POINT / y.value;
    return result;
}
static struct real divide_real_by_int(struct real x, int n){
    struct real result;
    result.value = x.value/n;
    return result;
}
#endif
