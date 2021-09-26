//
// Created by stefan on 26/09/2021.
//
#include "scanner.h"
#include "puzzlesolver.h"
using namespace std;

const int scanner = 0;
const int puzzleSolver = 1;

const int programToRun = puzzleSolver;

int main(int argc, char *argv[]) {
    switch (programToRun) {
        case scanner:
            runScanner(argc, argv);
            break;
        case puzzleSolver:
            runPuzzle(argc, argv);
            break;
        default:
            break;
    }
}