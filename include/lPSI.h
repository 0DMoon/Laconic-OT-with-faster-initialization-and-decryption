#pragma once
#include <pbc.h>
#include <gmp.h>
#include <iostream>
using namespace std;
class SMEServer{
public:
    int n;              //行数
    int* S;             //数据，为01串
    pairing_t pairing;  
    mpz_t q;        
    element_t g;
    element_pp_t g_pp;  //双线性映射相关
    mpz_t alpha;       //msk alpha
    element_t *skAlpha=NULL;    //receiver持有的私钥表
    element_t *pkAlpha=NULL;    //双方都知道的公钥表
    element_t gAlpha;           //补丁，为了解决下一行的0位减去上一行的1位会出现g^alpha的问题，必须公布这个值才能正常解密，这样就不能做完整的laconicOT了
    mpz_t r;            //receiver使用的随机数
    mpz_t t;            //sender使用的随机数
    element_t h;        //receiver生成的信息摘要
    element_t* dec;     //为了方便计算，预生成的解码表


    SMEServer(int num, int* data){
        //build communication
        n = num;
        S = new int[num];
        for(int i=0; i<num; ++i)S[i]=data[i];
    }
    //初始化，导入receiver端的数据

    void init(){
        cout << "start initialization." << endl;
        char param[1024];
        size_t count = fread(param, 1, 1024, stdin);
        //使用a.param完成pbc的双线性群初始化
        //使用时需要手动选择读入a.param
        if (!count) pbc_die("input error");
        pairing_init_set_buf(pairing, param, count);
        mpz_init(q);
        mpz_init_set_str(q, "730750818665451621361119245571504901405976559617", 10);
        element_init_G1(g, pairing);
        element_random(g);
        element_pp_init(g_pp, g);
        cout << "init pairing" << endl;

        gmp_randstate_t state;
        gmp_randinit_default(state);
        clock_t time = clock();
        gmp_randseed_ui(state, time);
        //随机数生成器相关初始化
        cout << "init random gengerate" << endl;

        mpz_init(alpha);
        mpz_urandomm(alpha, state, q);
        //随机选择一个alpha

        mpz_t alphan;
        mpz_init(alphan);
        mpz_set(alphan, alpha);
        element_init_G1(gAlpha, pairing);
        element_pp_pow(gAlpha, alphan, g_pp);
        //gAlpha=g^alpha

        mpz_mul(alphan, alphan, alpha);
        mpz_mod(alphan, alphan, q);
        //sk[0]即第一个秘钥对应g^(alpha^2)
        skAlpha = new element_t[3*n];
        for(int i=0; i<3*n; ++i){
            element_init_G1(skAlpha[i], pairing);
            element_pp_pow(skAlpha[i], alphan, g_pp);
            mpz_mul(alphan, alphan, alpha);
            mpz_mod(alphan, alphan, q);
        }
        //sk[i]=g^(alpha^(i+2))
        cout << "innit skalpha" << endl;

        mpz_t alphaInv;
        mpz_init(alphaInv);
        mpz_invert(alphaInv, alpha, q);
        //求得alpha的逆元，为计算pk做准备
        mpz_t alphanInv;
        mpz_init(alphanInv);
        mpz_set(alphanInv, alphaInv);
        mpz_mul(alphanInv, alphanInv, alphaInv);
        mpz_mod(alphanInv, alphanInv, q);
        //pk[0]即第一个秘钥对应g^(alpha^2)

        pkAlpha = new element_t[3*n];
        for(int i=0; i<3*n; ++i){
            element_init_G1(pkAlpha[i], pairing);
            element_pp_pow(pkAlpha[i], alphanInv, g_pp);
            mpz_mul(alphanInv, alphanInv, alphaInv);
            mpz_mod(alphanInv, alphanInv, q);
        }
        //pk[i]=g^(alpha^-(i+2))
        cout << "init pkalpha" << endl;
    }

    void genHash(){
        cout << "genHash.." << endl;
        gmp_randstate_t state;
        gmp_randinit_default(state);
        mpz_init(r);
        //随机化receiver使用的随机数r
        mpz_urandomm(r, state, q);
        element_init_G1(h, pairing);
        element_set(h, skAlpha[S[0]]);
        for(int i=1; i<n; ++i){
            element_mul(h, h, skAlpha[3*i+S[i]]);
        }
        //\Pi(skAlpha[3*i+S[i]])
        element_mul_mpz(h, h, r);
        // genDecMul();
    }
        
    void genDecMul(){
        cout << "genDecMul.." << endl;
        dec = new element_t[n];

        for(int i=0; i<n; ++i){
            //对解码表dec遍历
            // if(S[i]==0)continue;
            //对应PSI中缺失的元素，直接略过
            element_init_G1(dec[i], pairing);
            element_set(dec[i], g);
            for(int j=0; j<n; ++j){
                // cout << "i:" << i << ",s[i]:" << S[i] << ",j:" << j << ",s[j]:" << S[j] << endl;
                //对h中的每一项，计算alpha_(s[j]-s[i])
                if(i==j)continue;   //g
                int z = 3*j+S[j]-(3*i+S[i]);
                // cout << "z:" << z << endl;
                // if(z==1){
                //     element_mul(dec[i], dec[i], gAlpha);
                // }
                // else if(z > 0){
                //     element_mul(dec[i], dec[i], skAlpha[z-2]);
                // }
                // else{
                //     element_mul(dec[i], dec[i], pkAlpha[-z-2]);
                // }
                if(z==0){
                    element_mul(dec[i], dec[i], g);
                }
                else if(z>0){
                    element_mul(dec[i], dec[i], skAlpha[z-2]);
                }
                else{
                    element_mul(dec[i], dec[i], pkAlpha[-z-2]);
                }
            }
            element_pow_mpz(dec[i], dec[i], r);
        }
    }

    void encrypt(int point, element_t& c1, element_t& c2){
        // element_t c1, c2;
        element_init_GT(c1, pairing);
        element_init_G1(c2, pairing);
        gmp_randstate_t state;
        gmp_randinit_default(state);

        mpz_init(t);
        mpz_urandomm(t, state, q);
        //随机化sender使用的随机数t
        element_pp_pow(c2, t, g_pp);
        //c2=g^t

        element_t gkt;
        element_init_G1(gkt, pairing);
        //gkt=g_(-k)^t
        element_set(gkt, pkAlpha[3*point+S[point]]);
        element_pow_mpz(gkt, gkt, t);

        element_pairing(c1, gkt, h);
        //c1=e(h, gkt)
        // cout << element_length_in_bytes(c1) << endl;
        // cout << element_length_in_bytes(c2) << endl;
        // cout << element_length_in_bytes_compressed(c1) << endl;
        // cout << element_length_in_bytes_compressed(c2) << endl;
        // element_set(c3, c1);
        // element_set(c4, c2);
    }

    int decrypt(element_t c1, element_t c2){
        // element_t tmp1;
        // element_init_GT(tmp1, pairing);
        // element_t tmp2;
        // element_init_GT(tmp2, pairing);
        // mpz_t tmpm;
        // gmp_randstate_t state;
        // gmp_randinit_default(state);

        // mpz_init(tmpm);
        // mpz_urandomm(tmpm, state, q);
        // element_set_mpz(tmp1,tmpm);
        // element_set_mpz(tmp2,tmpm);
        // cout << "cmp:" << element_cmp(tmp1, tmp2) << endl;

        element_t tmp;
        element_init_GT(tmp, pairing);
        for(int i=0; i<n; ++i){
            // if(S[i]==0)continue;
            element_pairing(tmp, c2, dec[i]);
            int res = element_cmp(tmp, c1);
            if(res ==0) return i;
        }
        return -1;
    }

    void test(){
        // //test inv, pkalpha and skalpha
        // element_t gtmp;
        // element_init_GT(gtmp, pairing);
        // element_pairing(gtmp, g, g);
        // for(int i=0; i<n; ++i){
        //     element_t tmp;
        //     element_init_GT(tmp, pairing);
        //     element_pairing(tmp, skAlpha[i], pkAlpha[i]);
        //     int res = element_cmp(gtmp, tmp);
        //     cout << res << " ";
        // }
        // cout << endl;
        // //pass

        
    }
};