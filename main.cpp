#include "test.h"
using namespace std;
int main(int argc, char** argv){
    // test();

    int flag;
    flag = argv[1][0]-'0';
    if(flag == 1)
        server();
    else
        client();

    return 0;
}