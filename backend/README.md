# To-Do List API

## Description

This project implements an API with endpoints for user authentication and tasks management, using Flask, SQLAlchemy and
JWT.

## Motivation

This project is aimed at learning Python and its accessory technologies (API, Flask) and building a portfolio.

Feel free to clone it and use it however you wish.

I clarify that I am not responsible for harmful use of the code or the API that it runs.

At the end of this README there will be a description of how to collaborate with this repository.

## Project Status

This project is currently in development. There may be bugs and unfinished features. However, contributions are welcome
as the project progresses.

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/herissonnobre/to-do-list-api.git
    ```

2. Navigate to the project directory:
    ```sh
    cd to-do-list-api
    ```

3. Create a virtual environment:
    ```sh
    python -m venv venv
    ```

4. Activate the virtual environment:
    - Windows:
        ```sh
        venv\Scripts\activate
        ```
    - Mac/Linux:
        ```sh
        source venv/bin/activate
        ```

5. Install the dependencies:
    ```sh
    pip install -r requirements.txt
    ```

6. Create a `.env` file based on the `.env.example` file:
    ```sh
    cp .env.example .env
    ```

7. Configure your environment variables in the `.env` file.

## Usage

1. Start the server:
    ```sh
    flask run
    ```

2. Access the application on your preferred API management app:
   [http://localhost:5000](http://localhost:5000)

## Running the tests

1. Run the tests with pytest:
    ```sh
    pytest
    ```

## Contact

Herisson Neves - [herisson.carvalho96@gmail.com](mailto:herisson.carvalho96@gmail.com)

Project Link: [https://github.com/herissonnobre/to-do-list-api.git](https://github.com/herissonnobre/to-do-list-api.git)