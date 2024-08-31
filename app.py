import hashlib
import sqlite3
import streamlit as st
from sqlite3 import Error
from datetime import datetime
from questions import questions

def create_connection():
    connection = None
    try:
        connection = sqlite3.connect('wnrs.db')
    except Error as e:
        st.error(f"ERROR CONNECTING TO DATABASE: {e}")
    return connection

def create_users_table(connection):
    try:
        cursor = connection.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        ''')
        connection.commit()
    except Error as e:
        st.error(f"ERROR CREATING USERS TABLE: {e}")

def register_user(connection, username, password):
    try:
        cursor = connection.cursor()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        cursor.execute('''
            INSERT INTO users (username, password) VALUES (?, ?)
        ''', (username, hashed_password))
        connection.commit()
    except Error as e:
        st.error(f"ERROR REGISTERING USER: {e}")

def authenticate_user(connection, username, password):
    try:
        cursor = connection.cursor()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        cursor.execute('''
            SELECT id FROM users WHERE username = ? AND password = ?
        ''', (username, hashed_password))
        result = cursor.fetchone()
        return result[0] if result else None
    except Error as e:
        st.error(f"ERROR AUTHENTICATING USER: {e}")
        return None

def create_questions_table(connection):
    try:
        cursor = connection.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS questions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                question TEXT NOT NULL,
                level TEXT NOT NULL
            )
        ''')
        connection.commit()
    except Error as e:
        st.error(f"ERROR CREATING QUESTIONS TABLE: {e}")

def create_answers_table(connection):
    try:
        cursor = connection.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS answers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                answer TEXT NOT NULL,
                question_id INTEGER NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (question_id) REFERENCES questions(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        connection.commit()
    except Error as e:
        st.error(f"ERROR CREATING ANSWERS TABLE: {e}")

def add_answer(connection, user_id, question_id, answer):
    try:
        cursor = connection.cursor()
        cursor.execute('''
            INSERT INTO answers (user_id, question_id, answer) VALUES (?, ?, ?)
        ''', (user_id, question_id, answer))
        connection.commit()
    except Error as e:
        st.error(f"ERROR ADDING ANSWER: {e}")

def add_question_if_not_exists(connection, question, level):
    try:
        cursor = connection.cursor()
        cursor.execute('''
            SELECT id FROM questions WHERE question = ? AND level = ?
        ''', (question, level))
        result = cursor.fetchone()
        if not result:
            cursor.execute('''
                INSERT INTO questions (question, level) VALUES (?, ?)
            ''', (question, level))
            connection.commit()
    except Error as e:
        st.error(f"ERROR ADDING QUESTION: {e}")

def load_questions_to_db(connection):
    for level, questions_list in questions.items():
        for question in questions_list:
            add_question_if_not_exists(connection, question, level)

def get_questions(connection):
    try:
        cursor = connection.cursor()
        cursor.execute('''
            SELECT id, question, level FROM questions
        ''',)
        return cursor.fetchall()
    except Error as e:
        st.error(f"ERROR FETCHING QUESTIONS: {e}")
        return []
    
def get_answers_for_question(connection, question_id):
    try:
        cursor = connection.cursor()
        cursor.execute('''
            SELECT username, answer, timestamp 
            FROM answers
            JOIN users ON answers.user_id = users.id
            WHERE question_id = ?
            ORDER BY timestamp
        ''', (question_id,))
        return cursor.fetchall()
    except Error as e:
        st.error(f"ERROR FETCHING ANSWERS: {e}")
        return []


def load_css(file_name):
    with open(file_name) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

LEVEL_DESCRIPTIONS = {
    '1': 'Level 1: Perception',
    '2': 'Level 2: Connection',
    '3': 'Level 3: Reflection',
    '4': 'Level 3: Finale',
}

def main():
    st.title("We're Not Really Strangers")
    load_css("style.css")
    connection = create_connection()
    create_users_table(connection)
    create_questions_table(connection)  
    create_answers_table(connection)
    
    load_questions_to_db(connection)

    if not 'user_id' in st.session_state:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        
        if st.button("Register"):
            if username and password:
                register_user(connection, username, password)
                user_id = authenticate_user(connection, username, password)
                if user_id:
                    st.session_state['user_id'] = user_id
                    st.success("User logged in successfully.")
                    st.rerun()
                else:
                    st.error("ERROR: Authentication failed")
                st.success("User registered successfully. Please login")
                st.rerun()
            else:
                st.error("ERROR: Missing fields")

        if st.button("Login"):
            user_id = authenticate_user(connection, username, password)
            if user_id:
                st.session_state['user_id'] = user_id
                st.success("User logged in successfully.")
                st.rerun()
            else:
                st.error("ERROR: Authentication failed")
    else:
        levels = sorted(set([question[2] for question in get_questions(connection)]))
        level_labels = [LEVEL_DESCRIPTIONS.get(level, level) for level in levels]
        selected_level = st.sidebar.selectbox("Choose level", level_labels)
        st.header(f":sparkling_heart: {selected_level}")
        selected_level = next(key for key, value in LEVEL_DESCRIPTIONS.items() if value == selected_level)

        questions = [question for question in get_questions(connection) if question[2] == selected_level]
        if questions:
            for question in questions:
                st.markdown(f"<div class='question'>{question[0]}. {question[1]}</div>", unsafe_allow_html=True)
                answers = get_answers_for_question(connection, question[0])
                answer_expander = st.expander("See previous answers")
                if answers:
                    for answer in answers:
                        timestamp = datetime.strptime(answer[2], '%Y-%m-%d %H:%M:%S')
                        formatted_timestamp = timestamp.strftime('%B %d, %Y %H:%M')
                        answer_expander.markdown(f"<div class='timestamp'>{formatted_timestamp}</div>", unsafe_allow_html=True)
                        answer_expander.markdown(f":blue[**{answer[0]}**]: {answer[1]} ")
                else:
                    answer_expander.markdown(":red[**No answers found.**]")
                answer = st.text_input(f"Enter your answer below", key=f"answer_{question[0]}")
                if st.button(f"Submit", key=f"submit_{question[0]}"):
                    if answer:
                        add_answer(connection, st.session_state['user_id'], question[0], answer)
                        st.success("Your answer was added successfully.")
                        st.rerun()
                    else:
                        st.error("Please provide an answer before submitting.")
        else:
            st.markdown(":red[No questions found.]")


if __name__ == "__main__":
    main()
