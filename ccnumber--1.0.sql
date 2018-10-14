-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION ccnumber" to load this file. \quit

CREATE TYPE ccnumber;

--
--  Input and output functions.
--
CREATE FUNCTION ccnumberin(cstring)
RETURNS ccnumber
AS 'byteain'
LANGUAGE internal IMMUTABLE STRICT PARALLEL SAFE;

CREATE FUNCTION ccnumberout(ccnumber)
RETURNS cstring
AS 'byteaout'
LANGUAGE internal IMMUTABLE STRICT PARALLEL SAFE;

CREATE FUNCTION ccnumberrecv(internal)
RETURNS ccnumber
AS 'bytearecv'
LANGUAGE internal STABLE STRICT PARALLEL SAFE;

CREATE FUNCTION ccnumbersend(ccnumber)
RETURNS bytea
AS 'byteasend'
LANGUAGE internal STABLE STRICT PARALLEL SAFE;

--
--  The type itself.
--

CREATE TYPE ccnumber (
    INPUT          = ccnumberin,
    OUTPUT         = ccnumberout,
    RECEIVE        = ccnumberrecv,
    SEND           = ccnumbersend,
    INTERNALLENGTH = VARIABLE,
    STORAGE        = extended,
    -- make it a non-preferred member of string type category
    CATEGORY       = 'S',
    PREFERRED      = false,
    COLLATABLE     = true
);


--
--  Implicit and assignment type casts.
--

CREATE CAST (ccnumber AS bytea)   WITHOUT FUNCTION AS IMPLICIT;
CREATE CAST (bytea AS ccnumber)   WITHOUT FUNCTION AS ASSIGNMENT;

--
-- Operator Functions.
--

CREATE FUNCTION ccnumber_eq( ccnumber, ccnumber )
RETURNS bool
AS 'MODULE_PATHNAME'
COST 10
LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

CREATE FUNCTION ccnumber_ne( ccnumber, ccnumber )
RETURNS bool
AS 'MODULE_PATHNAME'
COST 10
LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

CREATE FUNCTION ccnumber_lt( ccnumber, ccnumber )
RETURNS bool
AS 'MODULE_PATHNAME'
COST 10
LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

CREATE FUNCTION ccnumber_le( ccnumber, ccnumber )
RETURNS bool
AS 'MODULE_PATHNAME'
COST 10
LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

CREATE FUNCTION ccnumber_gt( ccnumber, ccnumber )
RETURNS bool
AS 'MODULE_PATHNAME'
COST 10
LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

CREATE FUNCTION ccnumber_ge( ccnumber, ccnumber )
RETURNS bool
AS 'MODULE_PATHNAME'
COST 10
LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

--
-- Operators.
--

CREATE OPERATOR = (
    LEFTARG    = ccnumber,
    RIGHTARG   = ccnumber,
    COMMUTATOR = =,
    NEGATOR    = <>,
    PROCEDURE  = ccnumber_eq,
    RESTRICT   = eqsel,
    JOIN       = eqjoinsel,
    HASHES,
    MERGES
);

CREATE OPERATOR <> (
    LEFTARG    = ccnumber,
    RIGHTARG   = ccnumber,
    NEGATOR    = =,
    COMMUTATOR = <>,
    PROCEDURE  = ccnumber_ne,
    RESTRICT   = neqsel,
    JOIN       = neqjoinsel
);

CREATE OPERATOR < (
    LEFTARG    = ccnumber,
    RIGHTARG   = ccnumber,
    NEGATOR    = >=,
    COMMUTATOR = >,
    PROCEDURE  = ccnumber_lt,
    RESTRICT   = scalarltsel,
    JOIN       = scalarltjoinsel
);

CREATE OPERATOR <= (
    LEFTARG    = ccnumber,
    RIGHTARG   = ccnumber,
    NEGATOR    = >,
    COMMUTATOR = >=,
    PROCEDURE  = ccnumber_le,
    RESTRICT   = scalarltsel,
    JOIN       = scalarltjoinsel
);

CREATE OPERATOR >= (
    LEFTARG    = ccnumber,
    RIGHTARG   = ccnumber,
    NEGATOR    = <,
    COMMUTATOR = <=,
    PROCEDURE  = ccnumber_ge,
    RESTRICT   = scalargtsel,
    JOIN       = scalargtjoinsel
);

CREATE OPERATOR > (
    LEFTARG    = ccnumber,
    RIGHTARG   = ccnumber,
    NEGATOR    = <=,
    COMMUTATOR = <,
    PROCEDURE  = ccnumber_gt,
    RESTRICT   = scalargtsel,
    JOIN       = scalargtjoinsel
);

--
-- Support functions for indexing.
--

CREATE FUNCTION ccnumber_cmp(ccnumber, ccnumber)
RETURNS int4
AS 'MODULE_PATHNAME'
COST 10
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

--
-- The btree indexing operator class.
--

CREATE OPERATOR CLASS ccnumber_ops
DEFAULT FOR TYPE ccnumber USING btree AS
    OPERATOR    1   <  (ccnumber, ccnumber),
    OPERATOR    2   <= (ccnumber, ccnumber),
    OPERATOR    3   =  (ccnumber, ccnumber),
    OPERATOR    4   >= (ccnumber, ccnumber),
    OPERATOR    5   >  (ccnumber, ccnumber),
    FUNCTION    1   ccnumber_cmp(ccnumber, ccnumber);

--
-- Aggregates.
--

CREATE FUNCTION ccnumber_smaller(ccnumber, ccnumber)
RETURNS ccnumber
AS 'MODULE_PATHNAME'
COST 10
LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

CREATE FUNCTION ccnumber_larger(ccnumber, ccnumber)
RETURNS ccnumber
AS 'MODULE_PATHNAME'
COST 10
LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

CREATE AGGREGATE min(ccnumber)  (
    SFUNC = ccnumber_smaller,
    STYPE = ccnumber,
    SORTOP = <,
    PARALLEL = SAFE,
    COMBINEFUNC = ccnumber_smaller
);

CREATE AGGREGATE max(ccnumber)  (
    SFUNC = ccnumber_larger,
    STYPE = ccnumber,
    SORTOP = >,
    PARALLEL = SAFE,
    COMBINEFUNC = ccnumber_larger
);
