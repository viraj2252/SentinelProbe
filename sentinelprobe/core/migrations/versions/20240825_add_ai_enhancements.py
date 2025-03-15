"""Add AI decision engine enhancement tables.

Revision ID: 20240825_add_ai_enhancements
Create Date: 2024-08-25
"""

from typing import List

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic
revision = "20240825_add_ai_enhancements"
down_revision = None  # Set this to the previous migration ID when integrating
branch_labels = None
depends_on = None


def direct_sql_upgrade() -> List[str]:
    """Return a list of SQL statements to execute directly.

    Returns:
        List[str]: SQL statements to create the AI enhancement tables and types.
    """
    return [
        # Create enum types if they don't exist
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'confidencelevel') THEN
                CREATE TYPE confidencelevel AS ENUM ('low', 'medium', 'high');
            END IF;
        END
        $$;
        """,
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'contexttype') THEN
                CREATE TYPE contexttype AS ENUM ('infrastructure', 'application', 'data', 'user', 'business');
            END IF;
        END
        $$;
        """,
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'decisionruletype') THEN
                CREATE TYPE decisionruletype AS ENUM ('service_detection', 'vulnerability_scan', 'exploitation',
                                     'post_exploitation', 'reporting', 'correlation', 'adaptive');
            END IF;
        END
        $$;
        """,
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'strategyphase') THEN
                CREATE TYPE strategyphase AS ENUM ('reconnaissance', 'vulnerability_scan', 'exploitation',
                                    'post_exploitation', 'reporting', 'adaptive_learning');
            END IF;
        END
        $$;
        """,
        # Create vulnerability_correlations table
        """
        CREATE TABLE IF NOT EXISTS vulnerability_correlations (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            description VARCHAR(1000) NOT NULL,
            pattern_type VARCHAR(100) NOT NULL,
            pattern_definition JSONB NOT NULL,
            severity_adjustment FLOAT NOT NULL DEFAULT 1.0,
            confidence confidencelevel NOT NULL DEFAULT 'medium',
            context_type contexttype NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            correlation_metadata JSONB NOT NULL DEFAULT '{}',
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
        """,
        # Create adaptive_rules table
        """
        CREATE TABLE IF NOT EXISTS adaptive_rules (
            id SERIAL PRIMARY KEY,
            base_rule_id INTEGER,
            name VARCHAR(255) NOT NULL,
            description VARCHAR(1000) NOT NULL,
            rule_type decisionruletype NOT NULL,
            conditions JSONB NOT NULL,
            actions JSONB NOT NULL,
            success_count INTEGER NOT NULL DEFAULT 0,
            failure_count INTEGER NOT NULL DEFAULT 0,
            effectiveness_score FLOAT NOT NULL DEFAULT 0.5,
            confidence confidencelevel NOT NULL DEFAULT 'medium',
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            version INTEGER NOT NULL DEFAULT 1,
            adaptive_metadata JSONB NOT NULL DEFAULT '{}',
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
        """,
        # Create contextual_scores table
        """
        CREATE TABLE IF NOT EXISTS contextual_scores (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            description VARCHAR(1000) NOT NULL,
            context_type contexttype NOT NULL,
            context_definition JSONB NOT NULL,
            scoring_function JSONB NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            score_metadata JSONB NOT NULL DEFAULT '{}',
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
        """,
        # Create indexes
        """
        CREATE INDEX IF NOT EXISTS ix_vulnerability_correlations_context_type
        ON vulnerability_correlations (context_type);
        """,
        """
        CREATE INDEX IF NOT EXISTS ix_vulnerability_correlations_is_active
        ON vulnerability_correlations (is_active);
        """,
        """
        CREATE INDEX IF NOT EXISTS ix_adaptive_rules_base_rule_id
        ON adaptive_rules (base_rule_id);
        """,
        """
        CREATE INDEX IF NOT EXISTS ix_adaptive_rules_effectiveness_score
        ON adaptive_rules (effectiveness_score);
        """,
        """
        CREATE INDEX IF NOT EXISTS ix_adaptive_rules_is_active
        ON adaptive_rules (is_active);
        """,
        """
        CREATE INDEX IF NOT EXISTS ix_adaptive_rules_rule_type
        ON adaptive_rules (rule_type);
        """,
        """
        CREATE INDEX IF NOT EXISTS ix_contextual_scores_context_type
        ON contextual_scores (context_type);
        """,
        """
        CREATE INDEX IF NOT EXISTS ix_contextual_scores_is_active
        ON contextual_scores (is_active);
        """,
        # Add values to DecisionRuleType enum if they don't exist
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'decisionruletype') THEN
                BEGIN
                    ALTER TYPE decisionruletype ADD VALUE IF NOT EXISTS 'correlation';
                EXCEPTION WHEN duplicate_object THEN
                    NULL;
                END;

                BEGIN
                    ALTER TYPE decisionruletype ADD VALUE IF NOT EXISTS 'adaptive';
                EXCEPTION WHEN duplicate_object THEN
                    NULL;
                END;
            END IF;
        END
        $$;
        """,
        # Add value to StrategyPhase enum if it doesn't exist
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'strategyphase') THEN
                BEGIN
                    ALTER TYPE strategyphase ADD VALUE IF NOT EXISTS 'adaptive_learning';
                EXCEPTION WHEN duplicate_object THEN
                    NULL;
                END;
            END IF;
        END
        $$;
        """,
    ]


def upgrade() -> None:
    """Create tables and enums for AI decision engine enhancements."""
    # Create vulnerability_correlations table
    op.create_table(
        "vulnerability_correlations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.String(length=1000), nullable=False),
        sa.Column("pattern_type", sa.String(length=100), nullable=False),
        sa.Column(
            "pattern_definition",
            postgresql.JSONB(),
            nullable=False,
            comment="JSON structure defining the pattern for correlating vulnerabilities",
        ),
        sa.Column(
            "severity_adjustment",
            sa.Float(),
            nullable=False,
            server_default="1.0",
            comment="Multiplier to adjust the severity when the pattern is matched",
        ),
        sa.Column(
            "confidence",
            sa.Enum("low", "medium", "high", name="confidencelevel"),
            nullable=False,
            server_default="medium",
        ),
        sa.Column(
            "context_type",
            sa.Enum(
                "infrastructure",
                "application",
                "data",
                "user",
                "business",
                name="contexttype",
            ),
            nullable=False,
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column(
            "correlation_metadata",
            postgresql.JSONB(),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")
        ),
        sa.Column(
            "updated_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # Create adaptive_rules table
    op.create_table(
        "adaptive_rules",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("base_rule_id", sa.Integer(), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.String(length=1000), nullable=False),
        sa.Column(
            "rule_type",
            sa.Enum(
                "service_detection",
                "vulnerability_scan",
                "exploitation",
                "post_exploitation",
                "reporting",
                "correlation",
                "adaptive",
                name="decisionruletype",
            ),
            nullable=False,
        ),
        sa.Column(
            "conditions",
            postgresql.JSONB(),
            nullable=False,
            comment="JSON structure defining rule conditions",
        ),
        sa.Column(
            "actions",
            postgresql.JSONB(),
            nullable=False,
            comment="JSON structure defining rule actions",
        ),
        sa.Column("success_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failure_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "effectiveness_score",
            sa.Float(),
            nullable=False,
            server_default="0.5",
            comment="Score between 0-1 measuring rule effectiveness",
        ),
        sa.Column(
            "confidence",
            sa.Enum("low", "medium", "high", name="confidencelevel"),
            nullable=False,
            server_default="medium",
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "adaptive_metadata", postgresql.JSONB(), nullable=False, server_default="{}"
        ),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")
        ),
        sa.Column(
            "updated_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # Create contextual_scores table
    op.create_table(
        "contextual_scores",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.String(length=1000), nullable=False),
        sa.Column(
            "context_type",
            sa.Enum(
                "infrastructure",
                "application",
                "data",
                "user",
                "business",
                name="contexttype",
            ),
            nullable=False,
        ),
        sa.Column(
            "context_definition",
            postgresql.JSONB(),
            nullable=False,
            comment="JSON structure defining the context parameters",
        ),
        sa.Column(
            "scoring_function",
            postgresql.JSONB(),
            nullable=False,
            comment="JSON structure defining how to calculate the score adjustment",
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column(
            "score_metadata", postgresql.JSONB(), nullable=False, server_default="{}"
        ),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")
        ),
        sa.Column(
            "updated_at", sa.DateTime(), nullable=False, server_default=sa.text("now()")
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # Create indexes
    op.create_index(
        op.f("ix_vulnerability_correlations_context_type"),
        "vulnerability_correlations",
        ["context_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_vulnerability_correlations_is_active"),
        "vulnerability_correlations",
        ["is_active"],
        unique=False,
    )

    op.create_index(
        op.f("ix_adaptive_rules_base_rule_id"),
        "adaptive_rules",
        ["base_rule_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_adaptive_rules_effectiveness_score"),
        "adaptive_rules",
        ["effectiveness_score"],
        unique=False,
    )
    op.create_index(
        op.f("ix_adaptive_rules_is_active"),
        "adaptive_rules",
        ["is_active"],
        unique=False,
    )
    op.create_index(
        op.f("ix_adaptive_rules_rule_type"),
        "adaptive_rules",
        ["rule_type"],
        unique=False,
    )

    op.create_index(
        op.f("ix_contextual_scores_context_type"),
        "contextual_scores",
        ["context_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_contextual_scores_is_active"),
        "contextual_scores",
        ["is_active"],
        unique=False,
    )

    # Add CORRELATION and ADAPTIVE to DecisionRuleType enum
    # Note: In a real production environment, you'd use a safer approach for enum modifications
    # This is simplified for our example
    op.execute("ALTER TYPE decisionruletype ADD VALUE IF NOT EXISTS 'correlation'")
    op.execute("ALTER TYPE decisionruletype ADD VALUE IF NOT EXISTS 'adaptive'")

    # Add ADAPTIVE_LEARNING to StrategyPhase enum
    op.execute("ALTER TYPE strategyphase ADD VALUE IF NOT EXISTS 'adaptive_learning'")


def downgrade() -> None:
    """Drop the AI decision engine enhancement tables.

    Note that we can't easily remove enum values in PostgreSQL.
    In a real environment, you'd handle this differently.
    """
    # Drop created tables
    op.drop_table("contextual_scores")
    op.drop_table("adaptive_rules")
    op.drop_table("vulnerability_correlations")

    # Note: We can't easily remove enum values in PostgreSQL
    # In a real environment, you'd handle this differently
