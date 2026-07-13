Feature: Python injection detection

  The production Python rules must catch classic injection sinks and
  attribute each finding to the file that actually contains it.

  Scenario: Command injection and SQL injection are both detected with correct file attribution
    Given a staged copy of the fixture "tests/test_files/python/fixtures/mixed_vulnerabilities.py" as "mixed_case.py"
    When I scan the staging directory as "python" with the production rules
    Then the findings should include a "Command Injection" finding in "mixed_case.py"
    And the findings should include a "SQL Injection" finding in "mixed_case.py"
