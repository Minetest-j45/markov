package main

import (
	"log"
	"math/rand"
	"os"
	"strings"
)

func markovTrain(file string) map[string][]string {
	m := make(map[string][]string)
	data, err := os.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}

	text := string(data)
	words := strings.Fields(text)

	for i := 0; i < len(words)-1; i++ {
		key := words[i]
		value := words[i+1]

		if _, ok := m[key]; ok {
			m[key] = append(m[key], value)
		} else {
			m[key] = []string{value}
		}
	}
	if err != nil {
		log.Fatal("Failed to train Markov text generator:", err)
	}

	return m
}

func markov(m map[string][]string, startWords []string) string {
	length := rand.Intn(21) + 20
	output := make([]string, 0, length)

	if len(startWords) == 0 {
		startWords = make([]string, 0, len(m))
		for key := range m {
			startWords = append(startWords, key)
		}
	}

	word := startWords[rand.Intn(len(startWords))]
	startWord := word

	for len(output) < length || !strings.Contains(word, ".") {
		choices := m[word]
		if len(choices) == 0 {
			break
		}
		next := choices[rand.Intn(len(choices))]
		output = append(output, next)
		word = next
	}

	return startWord + " " + strings.Join(output, " ")
}
