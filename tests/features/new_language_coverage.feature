Feature: New-language rule coverage

  PHP, Go, Ruby, C#, SQL, XML, properties, and config each ship their own rule packs. Each language's
  unsafe fixture must yield at least one finding in its expected category.

  Scenario: PHP taint rules catch the unsafe fixture
    Given a staged copy of the fixture "tests/test_files/strictness_languages/php/unsafe.php" as "php_case.php"
    When I scan the staging directory as "php" with the "rules/php/taint.ron" taint rule file
    Then the findings should include a "Tainted Data Flow" finding in "php_case.php"

  Scenario: Go rules catch the unsafe fixture
    Given a staged copy of the fixture "tests/test_files/strictness_languages/go/unsafe.go" as "go_case.go"
    When I scan the staging directory as "go" using every rule in its rules directory
    Then the findings should include a "Command Injection" finding in "go_case.go"
    And the findings should include a "SQL Injection" finding in "go_case.go"

  Scenario: Ruby rules catch the unsafe fixture
    Given a staged copy of the fixture "tests/test_files/strictness_languages/ruby/unsafe.rb" as "ruby_case.rb"
    When I scan the staging directory as "ruby" using every rule in its rules directory
    Then the findings should include a "Command Injection" finding in "ruby_case.rb"
    And the findings should include a "SQL Injection" finding in "ruby_case.rb"

  Scenario: C# rules catch the unsafe fixture
    Given a staged copy of the fixture "tests/test_files/strictness_languages/csharp/parity.cs" as "parity_case.cs"
    When I scan the staging directory as "csharp" using every rule in its rules directory
    Then the findings should include a "Command Injection" finding in "parity_case.cs"

  Scenario: SQL rules catch the unsafe fixture
    Given a staged copy of the fixture "tests/test_files/strictness_languages/sql/unsafe.sql" as "sql_case.sql"
    When I scan the staging directory as "sql" using every rule in its rules directory
    Then the findings should include a "SQL Injection" finding in "sql_case.sql"

  Scenario: XML rules catch the unsafe fixture
    Given a staged copy of the fixture "tests/test_files/strictness_languages/xml/unsafe.xml" as "xml_case.xml"
    When I scan the staging directory as "xml" using every rule in its rules directory
    Then the findings should include a "XML External Entity (XXE)" finding in "xml_case.xml"

  Scenario: Properties rules catch the unsafe fixture
    Given a staged copy of the fixture "tests/test_files/strictness_languages/properties/unsafe.properties" as "props_case.properties"
    When I scan the staging directory as "properties" using every rule in its rules directory
    Then the findings should include a "Insecure Configuration" finding in "props_case.properties"

  Scenario: Config rules catch the unsafe fixture
    Given a staged copy of the fixture "tests/test_files/strictness_languages/config/unsafe.config" as "config_case.config"
    When I scan the staging directory as "config" using every rule in its rules directory
    Then the findings should include a "Insecure Communication" finding in "config_case.config"
