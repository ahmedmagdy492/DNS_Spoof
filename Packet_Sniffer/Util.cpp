#include "Util.h"

int count_labels(char* domain) {
    int len = strlen(domain);
    int dots_found = 1;

    for (int i = 0; i < len; i++) {
        if (domain[i] == '.') {
            dots_found++;
        }
    }
    return dots_found;
}

char** extract_labels(char* domain, int labels_count) {
    char** labels = (char**)malloc(sizeof(char*) * labels_count);
    int counter = 0;

    for (int i = 0; i < labels_count; i++) {
        labels[i] = (char*)malloc(sizeof(char) * 253);
    }

    int labels_index = 0;
    int last_stop = 0;
    int chars_count = 0;

    for (int i = 0; i < strlen(domain); i++) {
        if (domain[i] == '.') {
            for (int j = 0; j < chars_count; j++) {
                labels[labels_index][j] = domain[last_stop + j];
            }
            last_stop = i + 1;
            labels[labels_index][chars_count] = '\0';
            labels_index++;
            chars_count = 0;
        }
        else {
            chars_count++;
        }
    }

    for (int j = 0; j < chars_count; j++) {
        labels[labels_index][j] = domain[last_stop + j];
    }
    labels[labels_index][chars_count] = '\0';
    labels_index++;

    return labels;
}

int copy(int write_start, char* dest, char* src) {
    for (int i = 0; i < strlen(src); i++) {
        dest[write_start] = src[i];
        write_start++;
    }

    return write_start;
}

char* create_labels_str(char** labels, int count, int labels_count) {
    char* buffer = (char*)malloc(sizeof(char) * count);
    int buff_counter = 0;

    for (int i = 0; i < labels_count; i++) {
        buffer[buff_counter] = strlen(labels[i]);
        buff_counter++;
        buff_counter = copy(buff_counter, buffer, labels[i]);
    }

    buffer[buff_counter] = 0;

    return buffer;
}