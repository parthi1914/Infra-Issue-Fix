import logging
import streamlit as st

from services.db import is_db_available, run_query_list
from utils.constants import (
    SAMPLE_ENGINE_SERIALS,
    SAMPLE_TAIL_NUMBERS,
    ENGINE_TO_TAILS,
    TAIL_TO_ENGINES,
)

log = logging.getLogger(__name__)


@st.cache_data(ttl=300, show_spinner=False)
def get_engine_serials() -> list:
    if not is_db_available():
        return SAMPLE_ENGINE_SERIALS

    try:
        sql = """
            SELECT DISTINCT esn
              FROM asset_data_observability_model
             WHERE esn IS NOT NULL
             ORDER BY esn
        """
        result = run_query_list(sql)
        return result if result else SAMPLE_ENGINE_SERIALS
    except Exception as exc:
        log.warning("DB query failed, using sample data: %s", exc)
        return SAMPLE_ENGINE_SERIALS


@st.cache_data(ttl=300, show_spinner=False)
def get_tail_numbers() -> list:
    if not is_db_available():
        return SAMPLE_TAIL_NUMBERS

    try:
        sql = """
            SELECT DISTINCT tail_number
              FROM asset_data_observability_model
             WHERE tail_number IS NOT NULL
             ORDER BY tail_number
        """
        result = run_query_list(sql)
        return result if result else SAMPLE_TAIL_NUMBERS
    except Exception as exc:
        log.warning("DB query failed, using sample data: %s", exc)
        return SAMPLE_TAIL_NUMBERS


@st.cache_data(ttl=300, show_spinner=False)
def get_tails_for_engine(engine_serial: str) -> list:
    if not is_db_available():
        return ENGINE_TO_TAILS.get(engine_serial, [SAMPLE_TAIL_NUMBERS[0]])

    try:
        sql = """
            SELECT DISTINCT tail_number
              FROM asset_data_observability_model
             WHERE esn = :esn
               AND tail_number IS NOT NULL
             ORDER BY tail_number
        """
        result = run_query_list(sql, {"esn": engine_serial})
        return result if result else [SAMPLE_TAIL_NUMBERS[0]]
    except Exception as exc:
        log.warning("DB query failed, using sample data: %s", exc)
        return ENGINE_TO_TAILS.get(engine_serial, [SAMPLE_TAIL_NUMBERS[0]])


@st.cache_data(ttl=300, show_spinner=False)
def get_engines_for_tail(tail_number: str) -> list:
    if not is_db_available():
        return TAIL_TO_ENGINES.get(tail_number, [SAMPLE_ENGINE_SERIALS[0]])

    try:
        sql = """
            SELECT DISTINCT esn
              FROM asset_data_observability_model
             WHERE tail_number = :tail
               AND esn IS NOT NULL
             ORDER BY esn
        """
        result = run_query_list(sql, {"tail": tail_number})
        return result if result else [SAMPLE_ENGINE_SERIALS[0]]
    except Exception as exc:
        log.warning("DB query failed, using sample data: %s", exc)
        return TAIL_TO_ENGINES.get(tail_number, [SAMPLE_ENGINE_SERIALS[0]])
