CREATE OR REPLACE FUNCTION create_billing_hosp_entry()
RETURNS TRIGGER AS $$
BEGIN
    
    INSERT INTO billing (id, cost) VALUES (NEW.billing_id, 30);
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_create_billing_hosp_entry on public.hospitalization;

CREATE TRIGGER trigger_create_billing_hosp_entry
BEFORE INSERT ON hospitalization
FOR EACH ROW
EXECUTE FUNCTION create_billing_hosp_entry();