import dash
import dash_core_components as dcc
import dash_html_components as html
from dash.dependencies import Input, Output
import os

app = dash.Dash(__name__)

app.layout = html.Div([
    html.H1('Dash Application'),
    html.Div(id='output-container'),
    dcc.Input(id='input-box', type='text', value=''),
])

@app.callback(
    Output('output-container', 'children'),
    [Input('input-box', 'value')]
)
def update_output(value):
    return f'You have entered: {value}'

if __name__ == '__main__':
    app.run_server(debug=True, host='0.0.0.0')

