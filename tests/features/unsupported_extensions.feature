Feature: Unsupported file extensions

  File discovery is keyed off each language's known extensions. A file whose
  extension is not recognized for the scanned language must be skipped
  silently — never scanned, and never a scan error — even when its content
  looks just as dangerous as a supported file's.

  Scenario: A file with an unsupported extension is skipped, not errored
    Given a staged copy of the fixture "tests/test_files/python/fixtures/mixed_vulnerabilities.py" as "app.py"
    And a staged file "notes.txt" with unsupported-extension content that looks vulnerable
    When I scan the staging directory as "python" with the production rules
    Then the scan should succeed without error
    And the findings should include a "Command Injection" finding in "app.py"
    And no findings should reference "notes.txt"
