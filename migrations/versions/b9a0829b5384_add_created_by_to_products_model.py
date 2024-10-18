"""Add created_by to Products model

Revision ID: b9a0829b5384
Revises: 
Create Date: 2024-10-17 11:40:13.379222

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector

# revision identifiers, used by Alembic.
revision = 'b9a0829b5384'
down_revision = None
branch_labels = None
depends_on = None

def column_exists(table, column):
    bind = op.get_bind()
    inspector = Inspector.from_engine(bind)
    columns = inspector.get_columns(table)
    return any(c['name'] == column for c in columns)

def upgrade():
    # Check if the column already exists
    if not column_exists('products', 'created_by'):
        # Add the column as nullable first
        with op.batch_alter_table('products', schema=None) as batch_op:
            batch_op.add_column(sa.Column('created_by', sa.Integer(), nullable=True))

    # Update existing NULL values
    op.execute('UPDATE products SET created_by = 1 WHERE created_by IS NULL')

    # Now set the column to non-nullable
    with op.batch_alter_table('products', schema=None) as batch_op:
        batch_op.alter_column('created_by', existing_type=sa.Integer(), nullable=False)

    # Add the foreign key constraint if it doesn't exist
    with op.batch_alter_table('products', schema=None) as batch_op:
        fks = Inspector.from_engine(op.get_bind()).get_foreign_keys('products')
        if not any(fk['referred_table'] == 'user' and fk['referred_columns'] == ['id'] for fk in fks):
            batch_op.create_foreign_key('fk_products_created_by_user', 'user', ['created_by'], ['id'])

def downgrade():
    with op.batch_alter_table('products', schema=None) as batch_op:
        batch_op.drop_constraint('fk_products_created_by_user', type_='foreignkey')
        batch_op.drop_column('created_by')