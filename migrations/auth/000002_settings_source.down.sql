DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM auth.settings_source WHERE mode='env' AND initialized) THEN
  RAISE EXCEPTION 'adopt API configuration before removing ENV source protection';
 END IF;
END $$;
DROP TABLE auth.settings_source_audit;
DROP TABLE auth.settings_source;
