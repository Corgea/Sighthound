CREATE PROCEDURE dbo.LookupEmployee @name NVARCHAR(100)
AS
BEGIN
    DECLARE @sql NVARCHAR(MAX);
    SET @sql = N'SELECT id FROM employees WHERE name = ''' + @name + '''';
    EXEC sp_executesql @sql;
    SET @msg = 'user: ' || @name;
END
