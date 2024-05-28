CREATE OR REPLACE FUNCTION update_billing()
RETURNS TRIGGER AS $$
DECLARE
    bill_id UUID;
BEGIN
    
    SELECT billing_id INTO bill_id FROM hospitalization WHERE id = NEW.hospitalization_id;

    UPDATE billing
    SET cost = cost + 60
    WHERE id = bill_id::text;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_billing on public.surgery;

CREATE TRIGGER trigger_update_billing
BEFORE INSERT ON surgery
FOR EACH ROW
EXECUTE FUNCTION update_billing();
