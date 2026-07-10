Feature: Python injection detection

  The production Python rules must catch classic injection sinks and
  attribute each finding to the file that actually contains it.

  Scenario: Command injection and SQL injection are both detected with correct file attribution
    Given a staged copy of the fixture "tests/test_files/python/mixed_vulnerabilities.py" as "mixed_case.py"
    When I scan the staging directory as "python" with the production rules
    Then the findings should include a "Command Injection" finding in "mixed_case.py"
    And the findings should include a "SQL Injection" finding in "mixed_case.py"

  Scenario Outline: Dynamically formatted cursor execution is detected
    Given a staged copy of the fixture "<fixture>" as "unsafe_query.py"
    When I scan the staging directory as "python" with the production rules
    Then the findings should include a "SQL Injection" finding in "unsafe_query.py"

    Examples:
      | fixture                                                    |
      | tests/test_files/python/sql_percent_spaced.py              |
      | tests/test_files/python/sql_percent_unspaced.py            |
      | tests/test_files/python/sql_percent_variable.py            |
      | tests/test_files/python/sql_fstring_interpolation.py        |
      | tests/test_files/python/sql_concatenation.py                |
      | tests/test_files/python/sql_format_interpolation.py         |
