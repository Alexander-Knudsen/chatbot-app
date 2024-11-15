// static/js/script.js

document.addEventListener('DOMContentLoaded', function() {
    // Fetch the chat container
    const chatContainer = document.getElementById('chatContainer');

    if (!chatContainer) {
        console.error('Chat container not found.');
        return;
    }

    // Retrieve configuration from data attributes
    const botName = chatContainer.getAttribute('data-bot-name');
    const botId = chatContainer.getAttribute('data-bot-id');
    const apiUrl = chatContainer.getAttribute('data-api-url');
    const feedbackUrl = chatContainer.getAttribute('data-feedback-url');
    const clearUrl = chatContainer.getAttribute('data-clear-url');
    const directionsUrl = chatContainer.getAttribute('data-directions-url');
    const csrfToken = chatContainer.getAttribute('data-csrf-token');
    const renderImages = chatContainer.getAttribute('data-render-images') === 'true';

    // Verify all necessary configuration variables are present
    if (!botName || !botId || !apiUrl || !csrfToken) {
        console.error('Bot configuration variables are missing.');
        return;
    }

    // DOM elements
    const chatBtn = document.getElementById('chatBtn');
    const closeChatBtn = document.getElementById('closeChatBtn');
    const confirmPopup = document.getElementById('confirmPopup');
    const endChatBtn = document.getElementById('endChatBtn');
    const cancelBtn = document.getElementById('cancelBtn');
    const sendBtn = document.getElementById('sendBtn');
    const userInput = document.getElementById('userInput');
    const chatBody = document.getElementById('chatBody');

    // Verify all necessary DOM elements are present
    if (!chatBtn || !closeChatBtn || !confirmPopup || !endChatBtn || !cancelBtn || !sendBtn || !userInput || !chatBody) {
        console.error('One or more chat interface elements are missing.');
        return;
    }

    let latestUserMessage = ''; // To store the latest user message
    let awaitingUserLocation = false; // Track if the bot is awaiting user's location input
    let conversationEnded = false; // Track if the conversation has ended

    // Function to show the typing indicator
    function showTypingIndicator() {
        if (document.getElementById('typingIndicator')) return;

        const typingElement = document.createElement('div');
        typingElement.id = 'typingIndicator';
        typingElement.classList.add('chat-message', 'typing-indicator');

        typingElement.innerHTML = `
            <strong>${capitalizeFirstLetter(botName)}:</strong>
            <div class="typing-dots">
                <div></div><div></div><div></div>
            </div>
        `;

        chatBody.appendChild(typingElement);
        chatBody.scrollTop = chatBody.scrollHeight;
    }

    // Function to hide the typing indicator
    function hideTypingIndicator() {
        const typingElement = document.getElementById('typingIndicator');
        if (typingElement) {
            typingElement.remove();
        }
    }

    // Event: Open the chat container and fetch greeting
    chatBtn.addEventListener('click', function() {
        // Disable the chat button to prevent multiple clicks
        chatBtn.disabled = true;
        chatBtn.style.display = 'none'; // Hide the chat button

        chatContainer.style.display = 'flex'; // Show the chat container

        if (conversationEnded) {
            conversationEnded = false;
            chatBody.innerHTML = ''; // Clear chat messages
        }

        // Fetch the greeting message by sending a 'greet' message
        fetch(apiUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({ message: 'greet' })
        })
        .then(response => response.json())
        .then(data => {
            if (data.response) {
                appendMessage(botName, data.response);  // Display the bot's greeting
            } else if (data.error) {
                appendMessage('Error', 'Unable to fetch greeting. Please try again.');
                console.error('Error fetching greeting:', data.error);
            }
        })
        .catch(error => {
            console.error('Error fetching greeting:', error);
            appendMessage('Error', 'Unable to fetch greeting. Please try again.');
        });
    });

    // Event: Show confirmation popup when trying to close the chat
    closeChatBtn.addEventListener('click', function() {
        confirmPopup.style.display = 'block';
    });

    // Event: End the chat and clear session when "End Chat" is clicked
    endChatBtn.addEventListener('click', function() {
        confirmPopup.style.display = 'none';
        chatContainer.style.display = 'none'; // Hide the chat container
        chatBtn.style.display = 'flex'; // Show the chat button
        chatBtn.disabled = false; // Re-enable the chat button
        conversationEnded = true;
        chatBody.innerHTML = '';  // Clear chat messages

        // Clear the conversation on the backend (reset conversation)
        fetch(clearUrl, {
            method: 'POST',
            headers: {
                'X-CSRFToken': csrfToken
            }
        })
        .then(response => response.json())
        .then(data => {
            console.log('Session cleared:', data);
        })
        .catch(error => {
            console.error('Error clearing session:', error);
        });
    });

    // Event: Close confirmation popup when "Cancel" is clicked
    cancelBtn.addEventListener('click', function() {
        confirmPopup.style.display = 'none';
    });

    // Event: Send message when the send button is clicked
    sendBtn.addEventListener('click', function() {
        sendMessage();
    });

    // Event: Send message when Enter key is pressed
    userInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            sendMessage();
        }
    });

    // Send a message to the backend
    function sendMessage() {
        const message = userInput.value.trim();  // Get user input
        if (message === '') return;  // Ignore empty messages

        // Disable the input field and send button to prevent multiple messages
        userInput.disabled = true;
        sendBtn.disabled = true;
        sendBtn.style.cursor = 'not-allowed';
        sendBtn.style.opacity = '0.6';

        appendMessage('You', message);  // Display user's message
        latestUserMessage = message;    // Store the latest user message
        userInput.value = '';           // Clear input field

        // Show the typing indicator
        showTypingIndicator();

        if (awaitingUserLocation) {
            // If bot is awaiting location input, handle the directions logic
            requestDirections(message);
            awaitingUserLocation = false;
            hideTypingIndicator();
            // Re-enable input and send button
            userInput.disabled = false;
            sendBtn.disabled = false;
            sendBtn.style.cursor = 'pointer';
            sendBtn.style.opacity = '1';
            userInput.focus(); // Focus back on the input field
        } else {
            // Send message to the backend via POST request
            fetch(apiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ message: message })  // Send user message as JSON
            })
            .then(response => {
                if (!response.ok) {
                    // If response is not OK, try to parse JSON for error
                    return response.json().then(errData => {
                        throw new Error(errData.error || 'Unknown error');
                    });
                }
                return response.json();
            })
            .then(data => {
                hideTypingIndicator();  // Hide the typing indicator

                if (data.response) {
                    appendMessage(capitalizeFirstLetter(botName), data.response);  // Append bot's response

                    // Check if the bot is asking for the user's location
                    if (data.awaiting_location) {
                        awaitingUserLocation = true;
                    }
                } else if (data.error) {
                    appendMessage('Error', 'Message failed to send. Please try again.');
                    console.error('Error sending message:', data.error);
                }

                // Re-enable input and send button
                userInput.disabled = false;
                sendBtn.disabled = false;
                sendBtn.style.cursor = 'pointer';
                sendBtn.style.opacity = '1';
                userInput.focus();  // Bring focus back to the input field
            })
            .catch(error => {
                console.error('Error sending message:', error);
                hideTypingIndicator();  // Hide the typing indicator
                appendMessage('Error', 'Message failed to send. Please try again.');
                // Re-enable input and send button
                userInput.disabled = false;
                sendBtn.disabled = false;
                sendBtn.style.cursor = 'pointer';
                sendBtn.style.opacity = '1';
                userInput.focus();  // Bring focus back to the input field
            });
        }
    }

    // Request Google Maps directions
    function requestDirections(startingPoint) {
        // Send the starting point to the backend to generate Google Maps directions
        fetch(directionsUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({ user_location: startingPoint })  // Send user's starting point
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(errData => {
                    throw new Error(errData.error || 'Unknown error');
                });
            }
            return response.json();
        })
        .then(data => {
            if (data.response) {
                appendMessage(capitalizeFirstLetter(botName), data.response);  // Append directions link in the bot's response
            } else if (data.error) {
                appendMessage('Error', 'Unable to get directions. Please try again later.');
                console.error('Error fetching directions:', data.error);
            }
            // Re-enable input and send button
            userInput.disabled = false;
            sendBtn.disabled = false;
            sendBtn.style.cursor = 'pointer';
            sendBtn.style.opacity = '1';
            userInput.focus();  // Bring focus back to the input field
        })
        .catch(error => {
            console.error('Error fetching directions:', error);
            appendMessage('Error', 'Unable to get directions. Please try again later.');
            // Re-enable input and send button
            userInput.disabled = false;
            sendBtn.disabled = false;
            sendBtn.style.cursor = 'pointer';
            sendBtn.style.opacity = '1';
            userInput.focus();  // Bring focus back to the input field
        });
    }

    // Append a message to the chat
    function appendMessage(sender, message) {
        const messageElement = document.createElement('div');
        messageElement.classList.add('chat-message');

        if (sender === 'Error') {
            messageElement.classList.add('error-message');
        }

        // Convert Markdown to HTML using Marked library
        let sanitizedMessage = marked.parse(message);

        // Ensure all links open in a new tab
        sanitizedMessage = sanitizedMessage.replace(/<a /g, '<a target="_blank" ');

        // Add the message content (HTML formatting)
        messageElement.innerHTML = `<strong>${sender}:</strong> ${sanitizedMessage}`;

        // Only append images if they are allowed
        if (renderImages && sender === capitalizeFirstLetter(botName)) {
            const tempDiv = document.createElement('div');
            tempDiv.innerHTML = sanitizedMessage;
            const imgTags = tempDiv.querySelectorAll('img');

            if (imgTags.length > 0) {
                imgTags.forEach(imgTag => {
                    const imageElement = document.createElement('img');
                    imageElement.src = imgTag.getAttribute('src');
                    imageElement.alt = imgTag.getAttribute('alt') || 'Image';
                    imageElement.classList.add('chat-image');

                    // Avoid adding duplicates by checking if the image with the same URL already exists
                    if (!messageElement.querySelector(`img[src="${imageElement.src}"]`)) {
                        messageElement.appendChild(imageElement);
                    }
                });
            }
        }

        // If the message is from the bot, add thumbs up/down buttons
        if (sender === capitalizeFirstLetter(botName) && sender !== 'Error') {
            const feedbackContainer = document.createElement('div');
            feedbackContainer.classList.add('feedback-container');

            const thumbsUpBtn = document.createElement('button');
            thumbsUpBtn.classList.add('thumbs-up', 'btn', 'btn-success', 'btn-sm', 'me-2');
            thumbsUpBtn.innerHTML = '👍';
            thumbsUpBtn.setAttribute('aria-label', 'Positive Feedback');
            thumbsUpBtn.title = 'Positive Feedback';
            thumbsUpBtn.addEventListener('click', function() {
                sendFeedback('positive', message);  // Send 'positive' feedback to backend
                disableFeedbackButtons(feedbackContainer);
            });

            const thumbsDownBtn = document.createElement('button');
            thumbsDownBtn.classList.add('thumbs-down', 'btn', 'btn-danger', 'btn-sm');
            thumbsDownBtn.innerHTML = '👎';
            thumbsDownBtn.setAttribute('aria-label', 'Negative Feedback');
            thumbsDownBtn.title = 'Negative Feedback';
            thumbsDownBtn.addEventListener('click', function() {
                sendFeedback('negative', message);  // Send 'negative' feedback to backend
                disableFeedbackButtons(feedbackContainer);
                appendFollowUpFeedbackPrompt();  // Ask for more specific feedback
            });

            feedbackContainer.appendChild(thumbsUpBtn);
            feedbackContainer.appendChild(thumbsDownBtn);
            messageElement.appendChild(feedbackContainer);
        }

        chatBody.appendChild(messageElement);
        chatBody.scrollTop = chatBody.scrollHeight;  // Auto-scroll to the bottom
    }

    // Append a follow-up feedback prompt for negative feedback
    function appendFollowUpFeedbackPrompt() {
        const feedbackContainer = document.createElement('div');
        feedbackContainer.classList.add('feedback-container', 'mt-2');

        const feedbackInput = document.createElement('input');
        feedbackInput.setAttribute('type', 'text');
        feedbackInput.setAttribute('placeholder', 'Let me know how I can improve...');
        feedbackInput.classList.add('form-control', 'feedback-input', 'me-2');

        const submitFeedbackBtn = document.createElement('button');
        submitFeedbackBtn.innerHTML = 'Submit';
        submitFeedbackBtn.classList.add('btn', 'btn-primary', 'btn-sm', 'me-2');

        const closeFeedbackBtn = document.createElement('button');
        closeFeedbackBtn.innerHTML = '✖';
        closeFeedbackBtn.classList.add('btn', 'btn-secondary', 'btn-sm');
        closeFeedbackBtn.setAttribute('aria-label', 'Close Feedback');
        closeFeedbackBtn.title = 'Close Feedback';
        closeFeedbackBtn.addEventListener('click', function() {
            feedbackContainer.remove();
        });

        submitFeedbackBtn.addEventListener('click', function() {
            const feedbackText = feedbackInput.value.trim();
            if (feedbackText) {
                sendDetailedFeedback('negative', latestUserMessage, feedbackText);
                appendMessage(capitalizeFirstLetter(botName), "Thank you for your feedback! I'll strive to improve.");
                feedbackContainer.remove();
            }
        });

        feedbackInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                submitFeedbackBtn.click();
            }
        });

        feedbackContainer.appendChild(feedbackInput);
        feedbackContainer.appendChild(submitFeedbackBtn);
        feedbackContainer.appendChild(closeFeedbackBtn);
        chatBody.appendChild(feedbackContainer);
        feedbackInput.focus();
        chatBody.scrollTop = chatBody.scrollHeight;
    }

    // Send feedback to the backend
    function sendFeedback(feedbackType, botResponse) {
        fetch(feedbackUrl, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken 
            },
            body: JSON.stringify({ 
                feedback: feedbackType, 
                user_message: latestUserMessage, 
                bot_response: botResponse 
            })
        })
        .then(response => response.json())
        .then(data => {
            console.log('Feedback sent:', data);
        })
        .catch(error => {
            console.error('Error sending feedback:', error);
        });
    }

    // Send detailed feedback to the backend
    function sendDetailedFeedback(feedbackType, userMessage, feedbackText) {
        fetch(feedbackUrl, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken 
            },
            body: JSON.stringify({ 
                feedback: feedbackType, 
                user_message: userMessage, 
                user_feedback: feedbackText 
            })
        })
        .then(response => response.json())
        .then(data => {
            console.log('Detailed feedback sent:', data);
        })
        .catch(error => {
            console.error('Error sending detailed feedback:', error);
        });
    }

    // Disable feedback buttons after submission
    function disableFeedbackButtons(feedbackContainer) {
        const buttons = feedbackContainer.querySelectorAll('button');
        buttons.forEach(button => button.disabled = true);
    }

    // Helper Function: Capitalize first letter
    function capitalizeFirstLetter(string) {
        return string.charAt(0).toUpperCase() + string.slice(1);
    }
});
