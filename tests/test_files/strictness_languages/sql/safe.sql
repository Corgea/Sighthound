INSERT INTO audit_log (actor_id, action) VALUES (@actor, 'login');
SELECT id, email FROM users WHERE tenant_id = @tenant AND active = 1;
