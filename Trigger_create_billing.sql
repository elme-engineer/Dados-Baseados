CREATE OR REPLACE FUNCTION create_billing_entry()
RETURNS TRIGGER AS $$
BEGIN
    
    INSERT INTO billing (id, price) VALUES (NEW.billing_id, 20);
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_create_billing_entry on public.appointment;

CREATE TRIGGER trigger_create_billing_entry
BEFORE INSERT ON appointment
FOR EACH ROW
EXECUTE FUNCTION create_billing_entry();