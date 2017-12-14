--
-- PostgreSQL database dump
--

-- Dumped from database version 9.6.6
-- Dumped by pg_dump version 9.6.6

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


SET search_path = public, pg_catalog;

--
-- Name: tornode_seq; Type: SEQUENCE; Schema: public; Owner: jtk
--

CREATE SEQUENCE tornode_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE tornode_seq OWNER TO jtk;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: tornode; Type: TABLE; Schema: public; Owner: jtk
--

CREATE TABLE tornode (
    row_id bigint DEFAULT nextval('tornode_seq'::regclass) NOT NULL,
    stamp timestamp without time zone DEFAULT date_trunc('seconds'::text, now()) NOT NULL,
    rname text,
    cc text,
    bandwidth bigint,
    uptime bigint,
    ipaddr inet,
    hostname text,
    orport integer,
    dirport integer,
    auth boolean,
    exit boolean,
    fast boolean,
    guard boolean,
    named boolean,
    stable boolean,
    running boolean,
    valid boolean,
    v2dir boolean,
    platform text,
    hibernating boolean,
    badexit boolean,
    firstseen date,
    asname text,
    asn bigint,
    consensus bigint,
    address text
);


ALTER TABLE tornode OWNER TO jtk;

--
-- Name: x509cert_seq; Type: SEQUENCE; Schema: public; Owner: jtk
--

CREATE SEQUENCE x509cert_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE x509cert_seq OWNER TO jtk;

--
-- Name: x509cert; Type: TABLE; Schema: public; Owner: jtk
--

CREATE TABLE x509cert (
    row_id bigint DEFAULT nextval('x509cert_seq'::regclass) NOT NULL,
    stamp timestamp without time zone DEFAULT date_trunc('seconds'::text, now()) NOT NULL,
    hostname text,
    addr inet,
    port integer,
    pem text,
    serial text,
    version integer,
    md5 text,
    sha1 text,
    issuer text,
    issuer_cn text,
    issuer_c text,
    issuer_o text,
    subject text,
    cn text,
    altnames text,
    c text,
    o text,
    email text,
    notafter timestamp without time zone,
    notbefore timestamp without time zone,
    sigalgo text,
    datasrc text
);


ALTER TABLE x509cert OWNER TO jtk;

--
-- Name: tornode tornode_pkey; Type: CONSTRAINT; Schema: public; Owner: jtk
--

ALTER TABLE ONLY tornode
    ADD CONSTRAINT tornode_pkey PRIMARY KEY (row_id);


--
-- Name: x509cert x509cert_pkey; Type: CONSTRAINT; Schema: public; Owner: jtk
--

ALTER TABLE ONLY x509cert
    ADD CONSTRAINT x509cert_pkey PRIMARY KEY (row_id);


--
-- PostgreSQL database dump complete
--

