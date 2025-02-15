from app.utils.validations import is_valid_email, is_valid_password


def test_is_valid_email():
    """
    Tests email validator.
    """
    assert is_valid_email('test@example.com') == True
    assert is_valid_email('user.name+tag+sorting@example.com') == True
    assert is_valid_email('user.name@example.co.in') == True
    assert is_valid_email('user.name@example') == False
    assert is_valid_email('user@.example.com') == False
    assert is_valid_email('user@com') == False
    assert is_valid_email('user@.com') == False
    assert is_valid_email('@example.com') == False


def test_is_valid_password():
    """
    Tests password validator.
    """
    assert is_valid_password('SecurePassword@123') == True
    assert is_valid_password('Password123!') == True
    assert is_valid_password('Passw0rd!') == True

    # Tests password with less than 8 characters
    assert is_valid_password('Short1!') == False

    # Tests password without uppercase letter
    assert is_valid_password('password123!') == False

    # Tests password without lowercase letter
    assert is_valid_password('PASSWORD123!') == False

    # Tests password without number
    assert is_valid_password('Password!') == False

    # Tests password without special symbol
    assert is_valid_password('Password123') == False
