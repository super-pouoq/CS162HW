/*
 * Word count application with one thread per input file.
 *
 * You may modify this file in any way you like, and are expected to modify it.
 * Your solution must read each input file from a separate thread. We encourage
 * you to make as few changes as necessary.
 */

/*
 * Copyright © 2021 University of California, Berkeley
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <pthread.h>

#include "word_count.h"
#include "word_helpers.h"

#define MAX_THREADS 128
/*
 * main - handle command line, spawning one thread per file.
 */
struct thread_arg {
  word_count_list_t* wclist;
  char* filename;
};



void* thread_count_words(void* arg) {
  struct thread_arg* targ = (struct thread_arg*)arg;
  FILE* infile = fopen(targ->filename, "r");
  if (infile == NULL) {
    fprintf(stderr, "Could not open file %s\n", targ->filename);
    pthread_exit(NULL);
  }
  count_words(targ->wclist, infile);
  fclose(infile);
  free(targ);
  pthread_exit(NULL);
}
word_count_list_t word_counts;
int main(int argc, char* argv[]) {
  /* Create the empty data structure. */
  
  init_words(&word_counts);
  pthread_t threads[MAX_THREADS];
  int num_threads = 1;

  if (argc <= 1) {
    /* Process stdin in a single thread. */
    count_words(&word_counts, stdin);
  } else {
    num_threads = argc - 1;
    if (num_threads > MAX_THREADS) {
      num_threads = MAX_THREADS;
    }
    for(int i = 0; i < num_threads; i++) {
      /* Create a thread to process each file. */
      char* filename = argv[i + 1];
      struct thread_arg* arg = malloc(sizeof(struct thread_arg));
      arg->wclist = &word_counts;
      arg->filename = filename;
      pthread_create(&threads[i], NULL, thread_count_words, (void*)arg);
    }
    for (int i = 0; i < num_threads; i++) {
      pthread_join(threads[i], NULL);
    }
  }

  /* Output final result of all threads' work. */
  wordcount_sort(&word_counts, less_count);
  fprint_words(&word_counts, stdout);
  return 0;
}
