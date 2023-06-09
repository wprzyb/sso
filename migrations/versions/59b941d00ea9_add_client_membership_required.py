"""add client.membership_required

Revision ID: 59b941d00ea9
Revises: dd58bc95a904
Create Date: 2022-04-28 20:59:06.161062

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '59b941d00ea9'
down_revision = 'dd58bc95a904'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('oauth2_client', sa.Column('membership_required', sa.Boolean(), server_default='1', nullable=False))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('oauth2_client', 'membership_required')
    # ### end Alembic commands ###
