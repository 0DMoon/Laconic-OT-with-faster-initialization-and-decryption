#include "test.h"
#include <time.h>
#include "common.h"
using namespace std;
int num=1024;
int m = 32;

void test(){
    srand(time(NULL));
    int num=128;
    cout << num << endl;
    int* data = new int[num];
    for(int i=0; i<num; ++i){
        data[i]=rand()%2;
    }
    SMEServer server(num, data);
    server.init(); 
    server.genHash();
    server.test();
}

void server(){
    srand(time(NULL));
    cout << num << endl;
    int* data = new int[num];
    for(int i=0; i<num; ++i){
        data[i]=rand()%2;
    }
    //build connection
    // int fd = tcp_server(4568);

    int commSize = 0;
    //preprocessing
    SMEServer server(num, data);
    double initTime;
    clock_t t0;
    t0 = clock();
    server.init();
    clock_t t1;
    t1 = clock(); 
    initTime = (double)(t1-t0)/CLOCKS_PER_SEC;
    cout << "Init time:" << initTime << endl;
    server.genHash();
    clock_t t2;
    // t2 = clock();
    // double hashTime = (double)(t2-t1)/CLOCKS_PER_SEC;

    // t1 = clock();
    server.genDecMul();
    t2 = clock();
    double preTime;
    preTime = (double)(t2-t1)/CLOCKS_PER_SEC;

    //send hash
    // write(fd, (void*)server.h, sizeof(server.h));
    // cout << element_length_in_bytes(server.h) << endl;
    // cout << element_length_in_bytes_compressed(server.h) << endl;
    // cout << sizeof(server.h) << endl;
    // cout << sizeof(element_t) << endl;
    
    commSize += element_length_in_bytes(server.h);
    clock_t t3;
    t3 = clock();
    double encTime=0, decTime=0;

    element_t c1, c2;
    for(int i=0; i<m; ++i){
        int point=0;
        // while(true){
        //     point = rand()%num;
        //     if(data[point]==1)break;
        // }
        point = rand()%num;
        // cout << "point:" << point << endl;
        t3=clock();
        server.encrypt(point, c1, c2);
        clock_t t4;
        t4 = clock();
        encTime += (double)(t4-t3)/CLOCKS_PER_SEC;

        //send cyhertext
        // write(fd, (void*)c1, sizeof(element_t));
        // write(fd, (void*)c2, sizeof(element_t));
        // cout << element_length_in_bytes(c1) << endl;
        // cout << element_length_in_bytes(c2) << endl;
        commSize = commSize + element_length_in_bytes(c1) + element_length_in_bytes(c2);
        clock_t t5;
        t5 = clock();

        int res = server.decrypt(c1, c2);
        // cout << "res:" << res <<endl;
        if(point != res){
            cout << "point:" << point << ", res:" << res << ", point value:" << data[point] << endl;
        }
        clock_t t6;
        t6=clock();
        decTime += (double)(t6-t5)/CLOCKS_PER_SEC;
    }
    cout << "Preprocessing time:" << preTime << endl;
    cout << "Encryption time:" << encTime << endl;
    cout << "Decryption Time:" << decTime << endl;

    double totalTime;
    totalTime = preTime + encTime + decTime;
    cout << "Totaltime:" << totalTime << endl;
    cout << "Comm size:" << commSize << endl;
    cout << sizeof(int) << endl;
}
void client(){
    int fd = tcp_client((char*)"127.0.0.1", 4568);
    cout << "connect" << endl;

    pairing_t pairing;
    char param[1024];
    size_t count = fread(param, 1, 1024, stdin);
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing, param, count);

    element_t h;
    element_init_G1(h, pairing);
    read(fd, (void*)h, sizeof(element_t));
    // cout << hatS << endl;
    // element_printf("%B\n", hatS);
    element_t c1, c2;
    element_init_GT(c1, pairing);
    element_init_G1(c2, pairing);
    for(int i=0; i<num; ++i){
        read(fd, (void*)c1, sizeof(element_t));
        read(fd, (void*)c2, sizeof(element_t));
    }
}