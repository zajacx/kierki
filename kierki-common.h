#ifndef KIERKI_KIERKI_COMMON_H
#define KIERKI_KIERKI_COMMON_H

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::time_point<Clock>;

#include <vector>
#include <string>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <sstream>

// Log messages container.
struct Logs {
    std::vector<std::string> logs;

    void add(std::string from, std::string to, TimePoint time_point, std::string log_message) {

        auto system_time_point = std::chrono::system_clock::now() + (time_point - Clock::now());
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(system_time_point.time_since_epoch()) % 1000;
        std::time_t time_t = std::chrono::system_clock::to_time_t(system_time_point);
        std::tm tm = *std::gmtime(&time_t);

        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S") 
            << '.' << std::setw(3) << std::setfill('0') << ms.count();

        std::string formatted_time = oss.str();

        std::string log_entry = "[" + from + "," + to + "," + formatted_time + "] " + log_message;

        logs.push_back(log_entry);
    }

    void write_to_stdout() {
        for (const std::string& log : logs) {
            std::cout << log;
        }
    }
};

// Representation of a card.
struct Card {
    std::string value;
    char suit;

    Card(std::string v, char s) : value(v), suit(s) {}
    
    bool operator==(const Card& other) const {
        return value == other.value && suit == other.suit;
    }

    bool operator<(const Card& other) const {
        return (value < other.value) || (value == other.value && suit < other.suit);
    }

    std::string to_string() {
        return value + std::string(1, suit);
    }
};

// Representation of player's hand.
struct Hand {
    std::vector<Card> cards;

    void add_card(const Card& card) {
        cards.push_back(card);
    }

    void remove_card(const std::string& value, char suit) {
        auto it = std::find(cards.begin(), cards.end(), Card(value, suit));
        if (it != cards.end()) {
            cards.erase(it);
        }
    }
    
    void remove_cards_in_taken(const std::vector<Card>& cards_in_taken) {
        for (const auto& table_card : cards_in_taken) {
            auto it = std::find(cards.begin(), cards.end(), table_card);
            if (it != cards.end()) {
                cards.erase(it);
            }
        }
    }

    bool contains(const std::string& value, char suit) {
        auto it = std::find(cards.begin(), cards.end(), Card(value, suit));
        return it != cards.end();
    }
};

#endif //KIERKI_KIERKI_COMMON_H
