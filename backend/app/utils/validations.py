import re


def is_valid_email(email: str) -> bool:
    """
    Validates email format

    :param email: str: Email to validate
    :return: bool: True if email is valid, False otherwise
    """
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

    return re.match(email_regex, email) is not None


def is_valid_password(password: str) -> bool:
    """
    Validates password format

    :param password: str: Password to validate
    :return: bool: True if password is valid, False otherwise
    """
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?:{}|<>]', password):
        return False
    return True
