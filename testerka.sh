#!/bin/bash

# Uruchomienie serwera w tle
./kierki-serwer -f rozgrywka-3.txt -p 3333 &
SERVER_PID=$!

# Poczekaj na uruchomienie serwera
sleep 2

# Uruchomienie czterech klientów w tle
./kierki-klient -h 127.0.0.1 -p 3333 -N -4 &
CLIENT1_PID=$!
./kierki-klient -h 127.0.0.1 -p 3333 -E -4 &
CLIENT2_PID=$!
./kierki-klient -h 127.0.0.1 -p 3333 -S -4 &
CLIENT3_PID=$!
./kierki-klient -h 127.0.0.1 -p 3333 -W -4 &
CLIENT4_PID=$!

# Oczekiwanie na zakończenie serwera
wait $SERVER_PID
SERVER_EXIT_CODE=$?

# Oczekiwanie na zakończenie wszystkich klientów
wait $CLIENT1_PID
CLIENT1_EXIT_CODE=$?

wait $CLIENT2_PID
CLIENT2_EXIT_CODE=$?

wait $CLIENT3_PID
CLIENT3_EXIT_CODE=$?

wait $CLIENT4_PID
CLIENT4_EXIT_CODE=$?

# Sprawdzenie kodów wyjścia
if [[ $SERVER_EXIT_CODE -eq 0 && $CLIENT1_EXIT_CODE -eq 0 && $CLIENT2_EXIT_CODE -eq 0 && $CLIENT3_EXIT_CODE -eq 0 && $CLIENT4_EXIT_CODE -eq 0 ]]; then
    echo "Test zakończony pomyślnie."
    exit 0
else
    echo "Test nie powiódł się."
    echo "Kod wyjścia serwera: $SERVER_EXIT_CODE"
    echo "Kod wyjścia klienta N: $CLIENT1_EXIT_CODE"
    echo "Kod wyjścia klienta E: $CLIENT2_EXIT_CODE"
    echo "Kod wyjścia klienta S: $CLIENT3_EXIT_CODE"
    echo "Kod wyjścia klienta W: $CLIENT4_EXIT_CODE"
    exit 1
fi
