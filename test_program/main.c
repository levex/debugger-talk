#include <stdlib.h>
#include <stdio.h>
#include <time.h>

static int target;

void
game(void)
{
    target = rand() % 100;

    while(1) {
        int guess, n;
        printf("Make a guess: ");
        n = scanf("%d", &guess);
        if (n <= 0)
            break;

        if (guess > target) {
            printf("It's lower!\n");
        } else if (guess < target) {
            printf("It's higher!\n");
        } else {
            printf("You've got it!\n");
            break;
        }
    }
}

int
main(int argc, char **argv)
{
    srand(time(NULL));

    printf("Hello, SCALE 16x!\n");

    game();

    return 0;
}
