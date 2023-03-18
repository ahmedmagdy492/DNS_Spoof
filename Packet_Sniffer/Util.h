#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int count_labels(char* domain);

char** extract_labels(char* domain, int labels_count);

int copy(int write_start, char* dest, char* src);

char* create_labels_str(char** labels, int count, int labels_count);