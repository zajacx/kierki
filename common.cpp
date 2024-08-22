/*
void test_parse_trick() {
    // Correct:
    int trick_number;
    std::string value;
    char suit;
    assert(parse_trick("TRICK15H\r\n", &trick_number, &value, &suit) == 0);
    assert(trick_number == 1);
    assert(value == "5");
    assert(suit == 'H');
    assert(parse_trick("TRICK125H\r\n", &trick_number, &value, &suit) == 0);
    assert(trick_number == 12);
    assert(value == "5");
    assert(suit == 'H');
    assert(parse_trick("TRICK110H\r\n", &trick_number, &value, &suit) == 0);
    assert(trick_number == 1);
    assert(value == "10");
    assert(suit == 'H');
    assert(parse_trick("TRICK1310H\r\n", &trick_number, &value, &suit) == 0);
    assert(trick_number == 13);
    assert(value == "10");
    assert(suit == 'H');
    assert(parse_trick("TRICK5KS\r\n", &trick_number, &value, &suit) == 0);
    assert(trick_number == 5);
    assert(value == "K");
    assert(suit == 'S');
    // Wrong:
    assert(parse_trick("aTRICK5KS\r\n", &trick_number, &value, &suit) == 1);
    assert(parse_trick("TRICK0KS\r\n", &trick_number, &value, &suit) == 1);
    assert(parse_trick("TRICKS\r\n", &trick_number, &value, &suit) == 1);
    assert(parse_trick("TRICK500S\r\n", &trick_number, &value, &suit) == 1);
    assert(parse_trick("TRICK59M\r\n", &trick_number, &value, &suit) == 1);
}

// ----------------------------- Tests -------------------------------

void test_parse_busy() {
    std::vector<char> busy_places;
    // Correct:
    assert(parse_busy("BUSYN\r\n", busy_places) == 0);
    for (char c : busy_places) {
        std::cout << c << " "; 
    }
    std::cout << "\n";
    busy_places.clear();
    assert(parse_busy("BUSYS\r\n", busy_places) == 0);
    for (char c : busy_places) {
        std::cout << c << " "; 
    }
    std::cout << "\n";
    busy_places.clear();
    assert(parse_busy("BUSYNES\r\n", busy_places) == 0);
    for (char c : busy_places) {
        std::cout << c << " "; 
    }
    std::cout << "\n";
    busy_places.clear();
    assert(parse_busy("BUSYNWES\r\n", busy_places) == 0);
    for (char c : busy_places) {
        std::cout << c << " "; 
    }
    std::cout << "\n";
    busy_places.clear();
    assert(parse_busy("BUSYWE\r\n", busy_places) == 0);
    for (char c : busy_places) {
        std::cout << c << " "; 
    }
    std::cout << "\n";
    busy_places.clear();
    // Wrong:
    assert(parse_busy("BUSY\r\n", busy_places) == 1);
    busy_places.clear();
    assert(parse_busy("BUS", busy_places) == 1);
    busy_places.clear();
    assert(parse_busy("BUSY\n", busy_places) == 1);
    busy_places.clear();
    assert(parse_busy("BUSYNESENSE\r\n", busy_places) == 1);
    busy_places.clear();
    assert(parse_busy("BUSYWXD\r\n", busy_places) == 1);
    busy_places.clear();
    assert(parse_busy("BUSYN\r", busy_places) == 1);
}

void test_parse_deal() {
    int round_type;
    char starting_player;
    Hand hand;
    // CORRECT:
    assert(parse_deal("DEAL3W2D3D4D5D6D7D8D9D10DJDQDKDAD\r\n", &round_type, &starting_player, hand) == 0);
    std::cout << "Round Type: " << round_type << std::endl;
    std::cout << "Starting Player: " << starting_player << std::endl;
    std::cout << "Hand Cards: ";
    for (const auto& card : hand.cards) {
        std::cout << card.value << card.suit << " ";
    }
    std::cout << std::endl;
    assert(parse_deal("DEAL1N2C2S5H4S6D10D8H7SKCAHASJCQD\r\n", &round_type, &starting_player, hand) == 0);
    std::cout << "Round Type: " << round_type << std::endl;
    std::cout << "Starting Player: " << starting_player << std::endl;
    std::cout << "Hand Cards: ";
    for (const auto& card : hand.cards) {
        std::cout << card.value << card.suit << " ";
    }
    std::cout << std::endl;
    assert(parse_deal("DEAL7SJCQDKHAS2D3C4S5H6H7H8S9C10D\r\n", &round_type, &starting_player, hand) == 0);
    std::cout << "Round Type: " << round_type << std::endl;
    std::cout << "Starting Player: " << starting_player << std::endl;
    std::cout << "Hand Cards: ";
    for (const auto& card : hand.cards) {
        std::cout << card.value << card.suit << " ";
    }
    std::cout << std::endl;
    // WRONG:
    assert(parse_deal("DEAL3N2C3D4H5S6C7D8H10CKDQHAKS\r\n", &round_type, &starting_player, hand) == 1);
    assert(parse_deal("DEAL3N2C3D4H5S6C7D8M9S10CKDQHAKS\r\n", &round_type, &starting_player, hand) == 1);
    assert(parse_deal("DEAL3N2C3D4H5S6C7D8H5C9S10CKDQHAKS\r\n", &round_type, &starting_player, hand) == 1);
    assert(parse_deal("aDEAL3N2C3D4H5S6C7D8H9S10CKDQHAKS\r\n", &round_type, &starting_player, hand) == 1);
    assert(parse_deal("DEAL3N2C3D4H5S6C7D8H9S10CKDQHAKS\r\n", &round_type, &starting_player, hand) == 1);
}

void test_parse_trick() {
    // Correct:
    int trick_number;
    std::vector<Card> on_table;
    assert(parse_trick("TRICK15H3H4H\r\n", &trick_number, on_table, true) == 0);
    std::cout << "trick number: " << trick_number << "\n";
    for (Card card : on_table) {
        std::cout << card.value << card.suit << " ";
    }
    std::cout << "\n";
    assert(parse_trick("TRICK1\r\n", &trick_number, on_table, true) == 0);
    std::cout << "trick number: " << trick_number << "\n";
    for (Card card : on_table) {
        std::cout << card.value << card.suit << " ";
    }
    std::cout << "\n";
    assert(parse_trick("TRICK12H\r\n", &trick_number, on_table, true) == 0);
    std::cout << "trick number: " << trick_number << "\n";
    for (Card card : on_table) {
        std::cout << card.value << card.suit << " ";
    }
    std::cout << "\n";
    assert(parse_trick("TRICK12H3H\r\n", &trick_number, on_table, true) == 0);
    std::cout << "trick number: " << trick_number << "\n";
    for (Card card : on_table) {
        std::cout << card.value << card.suit << " ";
    }
    std::cout << "\n";
    assert(parse_trick("TRICK\r\n", &trick_number, on_table, false) == 1);
    // Wrong:
    assert(parse_trick("aTRICK5KS\r\n", &trick_number, on_table, false) == 1);
    assert(parse_trick("TRICK0KS\r\n", &trick_number, on_table, false) == 1);
    assert(parse_trick("TRICKS\r\n", &trick_number, on_table, false) == 1);
    assert(parse_trick("TRICK500S\r\n", &trick_number, on_table, false) == 1);
    assert(parse_trick("TRICK59M\r\n", &trick_number, on_table, false) == 1);
}

void test_parse_wrong() {
    // Correct:
    int trick_number;
    assert(parse_wrong("WRONG1\r\n", &trick_number) == 0);
    assert(parse_wrong("WRONG2\r\n", &trick_number) == 0);
    assert(parse_wrong("WRONG3\r\n", &trick_number) == 0);
    assert(parse_wrong("WRONG4\r\n", &trick_number) == 0);
    assert(parse_wrong("WRONG10\r\n", &trick_number) == 0);
    assert(parse_wrong("WRONG12\r\n", &trick_number) == 0);
    assert(parse_wrong("WRONG13\r\n", &trick_number) == 0);
    // Wrong:
    assert(parse_wrong("WRONG0\r\n", &trick_number) == 1);
    assert(parse_wrong("WRON\r\n", &trick_number) == 1);
    assert(parse_wrong("aWRONG12\r\n", &trick_number) == 1);
    assert(parse_wrong("WRONG14\r\n", &trick_number) == 1);
}

void test_parse_taken() {
    // Correct:
    int trick_number;
    char taken_by;
    std::vector<Card> cards;
    assert(parse_taken("TAKEN15H3H4H9HS\r\n", &trick_number, cards, &taken_by, true) == 0);
    std::cout << "trick_number: " << trick_number << "\n";
    std::cout << "taken_by: " << taken_by << "\n";
    std::cout << "cards: ";
    for (Card card : cards) {
        std::cout << card.value << card.suit << " ";
    }
    std::cout << "\n";
    assert(parse_taken("TAKEN124C10CKCACN\r\n", &trick_number, cards, &taken_by, false) == 0);
    std::cout << "trick_number: " << trick_number << "\n";
    std::cout << "taken_by: " << taken_by << "\n";
    std::cout << "cards: ";
    for (Card card : cards) {
        std::cout << card.value << card.suit << " ";
    }
    std::cout << "\n";
    assert(parse_taken("TAKEN105C6D7H10SS\r\n", &trick_number, cards, &taken_by, false) == 0);
    std::cout << "trick_number: " << trick_number << "\n";
    std::cout << "taken_by: " << taken_by << "\n";
    std::cout << "cards: ";
    for (Card card : cards) {
        std::cout << card.value << card.suit << " ";
    }
    std::cout << "\n";
    assert(parse_taken("TAKEN12H3H4H5HW\r\n", &trick_number, cards, &taken_by, true) == 0);
    std::cout << "trick_number: " << trick_number << "\n";
    std::cout << "taken_by: " << taken_by << "\n";
    std::cout << "cards: ";
    for (Card card : cards) {
        std::cout << card.value << card.suit << " ";
    }
    std::cout << "\n";
    // Wrong:
    assert(parse_taken("TAKEN\r\n", &trick_number, cards, &taken_by, false) == 1);
    assert(parse_taken("TAKEN47H8H9H10HN\n", &trick_number, cards, &taken_by, false) == 1);
    assert(parse_taken("aTAKEN15H3H4H9HS\r\n", &trick_number, cards, &taken_by, false) == 1);
    assert(parse_taken("TAKEN10HKDAHQDE\r\n", &trick_number, cards, &taken_by, false) == 1);
}

void test_parse_score() {
    int scores[5];
    // Correct:
    assert(parse_score("SCOREN35E22S41W17\r\n", scores) == 0);
    std::cout << "TEST 1:\n";
    for (int i = 1; i <= 4; i++) {
        std::cout << scores[i] << " ";
    }
    std::cout << "\n";
    assert(parse_score("SCOREW0E12345S0N17\r\n", scores) == 0);
    std::cout << "TEST 2:\n";
    for (int i = 1; i <= 4; i++) {
        std::cout << scores[i] << " ";
    }
    std::cout << "\n";
    assert(parse_score("SCOREN2E2222S41W0\r\n", scores) == 0);
    std::cout << "TEST 3:\n";
    for (int i = 1; i <= 4; i++) {
        std::cout << scores[i] << " ";
    }
    std::cout << "\n";
    // Wrong:
    assert(parse_score("aSCOREN2E2222S41W0\r\n", scores) == 1);
    assert(parse_score("SCOREN2N2222S41W0\r\n", scores) == 1);
    assert(parse_score("SCOREN2E2222S41W0\n", scores) == 1);
    assert(parse_score("SCORENE2222S41W2\r\n", scores) == 1);
    assert(parse_score("SCOREN2E2222N41W0\r\n", scores) == 1);
}
*/