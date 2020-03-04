/* gcc -fpie -pie -z now -fstack-protector-all -o samsara samsara.c */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void menu()
{
    puts("1. Capture a human");
    puts("2. Eat a human");
    puts("3. Cook a human");
    puts("4. Find your lair");
    puts("5. Move to another kingdom");
    puts("6. Commit suicide");
    printf("choice > ");
}

const int maxn = 7;
int cnt = 0;
unsigned long long* warehouse[8];

int main()
{
    setvbuf(stdout, NULL, _IONBF, 0);
    gid_t gid = getegid();
    setresgid(gid, gid, gid);

    unsigned long long lair;
    unsigned long long target = 0;
    unsigned long long dest;
    int op, index;
    
    puts("After defeating the Demon Dragon, you turned yourself into the Demon Dragon...");
    while (1) {
        unsigned long long ingr = 0;
        menu();
        scanf("%d", &op);
        switch (op) {
            case 1:
                if (cnt < maxn) {
                    warehouse[cnt] = malloc(8);
                    ++cnt;
                    puts("Captured.");
                }
                else puts("You can't capture more people.");
                break;
            case 2: 
                puts("Index:");
                scanf("%d", &index);
                free(warehouse[index]);
                puts("Eaten.");
                break;
            case 3:
                puts("Index:");
                scanf("%d", &index);
                puts("Ingredient:");
                scanf("%llu", &ingr);
                *(warehouse[index]) = ingr;
                puts("Cooked.");
                break;
            case 4: 
                printf("Your lair is at: %p\n", &lair);
                &target; // !
                break;
            case 5: 
                puts("Which kingdom?");
                scanf("%llu", &dest);
                lair = dest;
                puts("Moved.");
                break;
            case 6:
                if (target == 0xdeadbeef) system("/bin/sh");
                puts("Now, there's no Demon Dragon anymore...");
            default: exit(1);
        }
    }

    return 0;
}